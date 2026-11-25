//! `ServiceAuth`: the accounts [`Authorizer`] as a
//! [weirdnet-service](https://crates.io/crates/weirdnet-service) `Authorize` hook (feature
//! `service`).
//!
//! The service presents the caller's user card (and any memberships) once per stream;
//! `ServiceAuth` checks the card against the transport-authenticated peer, maps the access's
//! resource to an account, and lets the [`Authorizer`] resolve account plus identity to a role
//! from the store (recorded members, or presented owner-signed memberships under the
//! `Signed` or `Either` policy, with stored revocations applied). Use it instead of
//! weirdnet-service's `MembershipAuth` when accounts live in a [`Store`](crate::store::Store);
//! the decision itself is still weirdnet-access `enforce::decide`.

use crate::account::{AccountId, now_ms};
use crate::authz::{Authorize as _, Authorizer, Caller as AccountCaller, Refusal, Request};
use crate::net::{caller_from_presented, revocations};
use weirdnet_net::PeerId;
use weirdnet_net::member::{Membership, Presented};
use weirdnet_net::profile::Profile;
use weirdnet_net::user::Card;
use weirdnet_service::codec::from_cbor;
use weirdnet_service::{Access, Admitted, Authorize, Caller, ServiceError};

/// A weirdnet-service hook over an [`Authorizer`].
#[derive(Debug, Clone)]
pub struct ServiceAuth {
    profile: &'static Profile,
    authz: Authorizer,
    app: Option<String>,
}

impl ServiceAuth {
    /// A hook over `authz`. Resources are bare account ids unless [`for_app`](Self::for_app)
    /// is set.
    pub fn new(profile: &'static Profile, authz: Authorizer) -> Self {
        ServiceAuth { profile, authz, app: None }
    }

    /// Resources are `<app>/account/<id>`, the same as signed memberships'
    /// ([`crate::net::resource`]).
    pub fn for_app(mut self, app: impl Into<String>) -> Self {
        self.app = Some(app.into());
        self
    }

    fn account_id(&self, resource: &str) -> Option<AccountId> {
        let id = match &self.app {
            Some(app) => resource.strip_prefix(app.as_str())?.strip_prefix("/account/")?,
            None => resource,
        };
        AccountId::new(id).ok()
    }

    fn card(&self, caller: &Caller, peer: &PeerId) -> Result<Option<Card>, ServiceError> {
        match caller.credentials.user_card() {
            None => Ok(None),
            Some(card) => {
                let card = card.map_err(|_| ServiceError::refused("wrong-user"))?;
                self.profile.check_card(&peer.to_string(), &card).map_err(|_| ServiceError::refused("wrong-user"))?;
                Ok(Some(card))
            }
        }
    }

    fn account_caller(&self, caller: &Caller, peer: &PeerId, card: Option<Card>, id: &AccountId, now: i64) -> Result<AccountCaller, ServiceError> {
        let Some(card) = card else { return Ok(AccountCaller::default()) };
        let plain = AccountCaller::user(card.id.clone());
        let store = self.authz.store();
        let Some(account) = store.account(id).map_err(|e| ServiceError::unavailable(e.to_string()))? else { return Ok(plain) };
        let mut presented = caller.credentials.memberships().filter_map(|b| from_cbor::<Membership>(b).ok()).peekable();
        if presented.peek().is_none() {
            return Ok(plain);
        }
        let stored = store.revocations(id).map_err(|e| ServiceError::unavailable(e.to_string()))?;
        let revoked = revocations(&account, &stored).map_err(|e| ServiceError::unavailable(e.to_string()))?;
        let app = self.app.as_deref().unwrap_or_default();
        for membership in presented {
            let p = Presented { membership, card: card.clone() };
            let checked = if self.app.is_some() {
                caller_from_presented(self.profile, &p, peer, app, &account, &revoked, now).ok()
            } else {
                // Bare ids: the membership's resource must be the account id itself.
                weirdnet_net::member::check_presented(self.profile, &p, peer, &account.owner, id.as_str(), &revoked, now).ok().map(|m| {
                    AccountCaller::user(m.user_id.clone()).with_presented(crate::authz::PresentedRole {
                        role: m.role,
                        issued_at_ms: m.issued_at,
                        expires_at_ms: m.expires_at,
                    })
                })
            };
            if let Some(c) = checked {
                return Ok(c);
            }
        }
        Ok(plain)
    }
}

impl Authorize for ServiceAuth {
    fn authorize(&self, caller: &Caller, access: &Access) -> Result<Admitted, ServiceError> {
        let peer: PeerId = caller.peer.parse().map_err(|_| ServiceError::refused("wrong-user"))?;
        let card = self.card(caller, &peer)?;
        let mut admitted = Admitted::new(caller.peer.clone());
        if let Some(c) = &card {
            admitted = admitted.with_user(c.id.clone());
        }
        let Some(resource) = &access.resource else { return Ok(admitted) };
        let id = self.account_id(resource).ok_or_else(|| ServiceError::not_found(resource.clone()))?;
        let now = now_ms();
        let who = self.account_caller(caller, &peer, card, &id, now)?;
        match self.authz.authorize(&Request { caller: &who, account: &id, perm: &access.permission, now_ms: now }) {
            Ok(ad) => Ok(admitted.with_resource(resource.clone()).with_role(ad.role())),
            Err(Refusal::NotFound) => Err(ServiceError::not_found(resource.clone())),
            Err(Refusal::Suspended) => Err(ServiceError::refused("suspended")),
            Err(Refusal::Denied(_)) => Err(ServiceError::refused("role")),
            Err(Refusal::Storage(m)) => Err(ServiceError::unavailable(m)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::MembershipPolicy;
    use crate::directory::Accounts;
    use crate::net::{sign_member, user_id_of};
    use crate::store::MemoryStore;
    use std::sync::Arc;
    use weirdnet_net::Keypair;
    use weirdnet_net::profile::WEIRDNET;
    use weirdnet_service::Credentials;

    fn card(user: &Keypair, node: &Keypair) -> Card {
        let uid = user_id_of(user);
        let peer = PeerId::from(node.public()).to_string();
        Card {
            id: uid.clone(),
            label: "laptop".into(),
            key: user.public().encode_protobuf(),
            nodes: vec![WEIRDNET.certify(user, &uid, &peer, "laptop", 1).unwrap()],
        }
    }

    #[test]
    fn service_hook() {
        let owner = Keypair::generate_ed25519();
        let (alice, alice_node) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
        let (bob, bob_node) = (Keypair::generate_ed25519(), Keypair::generate_ed25519());
        let c = crate::catalog::catalog();
        let store = Arc::new(MemoryStore::new());
        let acc = Accounts::new(store.clone(), c.clone());
        let id = AccountId::new("desk").unwrap();
        let a = acc.create(&user_id_of(&owner), id.clone(), "Desk", crate::catalog::standard(&c, &[]).unwrap(), 1).unwrap();
        acc.add_member(&a.owner, &id, &user_id_of(&alice), Some("viewer"), None, 2).unwrap();
        let hook = ServiceAuth::new(&WEIRDNET, acc.authorizer().clone().with_policy(MembershipPolicy::Either)).for_app("example-app");
        let res = crate::net::resource("example-app", &id);
        let alice_caller = Caller::new(PeerId::from(alice_node.public()).to_string(), Credentials::new().with_user_card(&card(&alice, &alice_node)));

        let ad = hook.authorize(&alice_caller, &Access::new("read").on(res.clone())).unwrap();
        assert_eq!(ad.role.as_deref(), Some("viewer"));
        assert_eq!(ad.user, Some(user_id_of(&alice)));
        assert!(hook.authorize(&alice_caller, &Access::new(crate::catalog::KEYS_MANAGE).on(res.clone())).is_err());
        assert!(hook.authorize(&alice_caller, &Access::session()).is_ok());
        assert!(hook.authorize(&alice_caller, &Access::new("read").on("other/account/desk")).is_err());

        // A card that certifies a different node is refused.
        let wrong = Caller::new(PeerId::from(bob_node.public()).to_string(), Credentials::new().with_user_card(&card(&alice, &alice_node)));
        assert!(hook.authorize(&wrong, &Access::session()).is_err());

        // Bob isn't recorded but presents an owner-signed membership.
        let bob_caller = Caller::new(PeerId::from(bob_node.public()).to_string(), Credentials::new().with_user_card(&card(&bob, &bob_node)));
        assert!(hook.authorize(&bob_caller, &Access::new("read").on(res.clone())).is_err());
        let mut m = crate::account::Member {
            account: id.clone(),
            user_id: user_id_of(&bob),
            role: "member".into(),
            added_by: a.owner.clone(),
            added_at_ms: 3,
            expires_at_ms: None,
            signed: None,
        };
        let signed = sign_member(&owner, "example-app", &a, &mut m).unwrap();
        let bob_signed = Caller::new(bob_caller.peer.clone(), bob_caller.credentials.clone().with_membership_of(&signed));
        assert_eq!(hook.authorize(&bob_signed, &Access::new("read").on(res.clone())).unwrap().role.as_deref(), Some("member"));
        // Removing him voids it.
        acc.remove_member(&a.owner, &id, &user_id_of(&bob), "", now_ms()).unwrap();
        assert!(hook.authorize(&bob_signed, &Access::new("read").on(res)).is_err());
    }
}
