//! Signed memberships with [weirdnet-net](https://crates.io/crates/weirdnet-net)
//! (feature `net`).
//!
//! An account's owner can sign each membership with their user key
//! (`member::Membership::issue`) and each removal (`member::MemberRevocation::revoke`), so a
//! member's node can present its membership on a stream and the host checks it against the
//! Noise-authenticated peer with `check_presented`. The membership's resource is
//! [`resource`]`(app, account)`, and its role is the account role id.
//!
//! Use [`caller_from_card`] when only the node cert is known, and [`caller_from_presented`]
//! when a membership was presented, then hand the [`Caller`] to the
//! [`Authorizer`](crate::authz::Authorizer) (with [`MembershipPolicy::Signed`](crate::authz::MembershipPolicy)
//! or `Either` to count presented memberships).

use crate::account::{Account, AccountError, AccountId, AccountResult, Member, Revocation};
use crate::authz::{Caller, PresentedRole};
use weirdnet_net::member::{MemberRevocation, Membership, Presented, Revocations, check_presented};
use weirdnet_net::profile::Profile;
use weirdnet_net::user::{Card, user_id};
use weirdnet_net::{Keypair, PeerId};

/// The membership resource for an account: `<app>/account/<id>`.
pub fn resource(app: &str, account: &AccountId) -> String {
    format!("{app}/account/{account}")
}

/// The Weirdnet user id of a user keypair.
pub fn user_id_of(kp: &Keypair) -> String {
    user_id(&kp.public())
}

fn net(e: weirdnet_net::NetError) -> AccountError {
    AccountError::Invalid(e.to_string())
}

fn check_owner(owner: &Keypair, account: &Account) -> AccountResult<()> {
    if user_id_of(owner) != account.owner {
        return Err(AccountError::Denied("only the account owner's key signs its memberships".into()));
    }
    Ok(())
}

/// The owner signs `member`'s membership (role, added time, expiry) and stores the JSON in
/// `member.signed`. Save the member afterwards.
pub fn sign_member(owner: &Keypair, app: &str, account: &Account, member: &mut Member) -> AccountResult<Membership> {
    check_owner(owner, account)?;
    if member.account != account.id {
        return Err(AccountError::Invalid("the member belongs to another account".into()));
    }
    let m = Membership::issue(owner, &resource(app, &account.id), &member.user_id, &member.role, member.added_at_ms, member.expires_at_ms)
        .map_err(net)?;
    member.signed = Some(serde_json::to_vec(&m).map_err(|e| AccountError::Invalid(e.to_string()))?);
    Ok(m)
}

/// The owner signs a removal and stores the JSON in `revocation.signed`; publish it to
/// members' hosts so presented memberships stop working everywhere.
pub fn sign_revocation(owner: &Keypair, app: &str, account: &Account, revocation: &mut Revocation) -> AccountResult<MemberRevocation> {
    check_owner(owner, account)?;
    let r = MemberRevocation::revoke(owner, &resource(app, &account.id), &revocation.user_id, revocation.before_ms, revocation.at_ms).map_err(net)?;
    revocation.signed = Some(serde_json::to_vec(&r).map_err(|e| AccountError::Invalid(e.to_string()))?);
    Ok(r)
}

/// The checked weirdnet-net [`Revocations`] from an account's stored signed revocations.
pub fn revocations(account: &Account, stored: &[Revocation]) -> AccountResult<Revocations> {
    let mut out = Revocations::new(&account.owner);
    for r in stored.iter().filter_map(|r| r.signed.as_deref()) {
        let r: MemberRevocation = serde_json::from_slice(r).map_err(|e| AccountError::Invalid(e.to_string()))?;
        out.add(r).map_err(net)?;
    }
    Ok(out)
}

/// The stored signed membership of a member, if any.
pub fn membership(member: &Member) -> AccountResult<Option<Membership>> {
    member.signed.as_deref().map(|b| serde_json::from_slice(b).map_err(|e| AccountError::Invalid(e.to_string()))).transpose()
}

/// A caller from the card a peer sent: the user it certifies, or an unknown caller if the
/// card doesn't certify `peer` (revoked or forged certs included).
pub fn caller_from_card(profile: &Profile, peer: &PeerId, card: &Card) -> Caller {
    match profile.check_card(&peer.to_string(), card) {
        Ok(key) => Caller::user(user_id(&key)),
        Err(_) => Caller::default(),
    }
}

/// A caller from a presented membership, checked with weirdnet-net `check_presented`
/// (signature, owner, resource, expiry, card for `peer`, signed revocations). The stored
/// unsigned revocations still apply in the authorizer.
pub fn caller_from_presented(
    profile: &Profile,
    presented: &Presented,
    peer: &PeerId,
    app: &str,
    account: &Account,
    revoked: &Revocations,
    now_ms: i64,
) -> AccountResult<Caller> {
    let m = check_presented(profile, presented, peer, &account.owner, &resource(app, &account.id), revoked, now_ms)
        .map_err(|e| AccountError::Denied(e.to_string()))?;
    Ok(Caller::user(m.user_id.clone()).with_presented(PresentedRole { role: m.role, issued_at_ms: m.issued_at, expires_at_ms: m.expires_at }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Authorize, MembershipPolicy, Request};
    use crate::directory::Accounts;
    use crate::store::{MemoryStore, Store};
    use std::sync::Arc;
    use weirdnet_net::profile::WEIRDNET;

    fn card(user: &Keypair, node: &Keypair, at: i64) -> Card {
        let uid = user_id_of(user);
        let peer = PeerId::from(node.public()).to_string();
        Card {
            id: uid.clone(),
            label: "phone".into(),
            key: user.public().encode_protobuf(),
            nodes: vec![WEIRDNET.certify(user, &uid, &peer, "phone", at).unwrap()],
        }
    }

    #[test]
    fn signed_membership_round_trip() {
        let owner = Keypair::generate_ed25519();
        let alice = Keypair::generate_ed25519();
        let alice_node = Keypair::generate_ed25519();
        let peer = PeerId::from(alice_node.public());
        let store = Arc::new(MemoryStore::new());
        let c = crate::catalog::catalog();
        let acc = Accounts::new(store.clone(), c.clone());
        let id = AccountId::new("desk").unwrap();
        let a = acc.create(&user_id_of(&owner), id.clone(), "Desk", crate::catalog::standard(&c, &[]).unwrap(), 1_000).unwrap();
        let mut m = acc.add_member(&a.owner, &id, &user_id_of(&alice), Some("member"), None, 2_000).unwrap();
        // Only the owner's key signs.
        assert!(sign_member(&alice, "example-app", &a, &mut m.clone()).is_err());
        let signed = sign_member(&owner, "example-app", &a, &mut m).unwrap();
        store.put_member(&m).unwrap();
        assert_eq!(membership(&store.member(&id, &m.user_id).unwrap().unwrap()).unwrap(), Some(signed.clone()));

        let presented = Presented { membership: signed, card: card(&alice, &alice_node, 1_500) };
        let revs = revocations(&a, &store.revocations(&id).unwrap()).unwrap();
        let caller = caller_from_presented(&WEIRDNET, &presented, &peer, "example-app", &a, &revs, 3_000).unwrap();
        assert_eq!(caller.user.as_deref(), Some(user_id_of(&alice).as_str()));
        let az = acc.authorizer().clone().with_policy(MembershipPolicy::Signed);
        assert_eq!(az.authorize(&Request { caller: &caller, account: &id, perm: "read", now_ms: 3_000 }).unwrap().role(), "member");
        // Wrong peer or wrong app resource fail.
        let other = PeerId::from(Keypair::generate_ed25519().public());
        assert!(caller_from_presented(&WEIRDNET, &presented, &other, "example-app", &a, &revs, 3_000).is_err());
        assert!(caller_from_presented(&WEIRDNET, &presented, &peer, "other-app", &a, &revs, 3_000).is_err());
        assert_eq!(caller_from_card(&WEIRDNET, &peer, &presented.card).user, caller.user);
        assert_eq!(caller_from_card(&WEIRDNET, &other, &presented.card).user, None);

        // A signed removal voids the presented membership at the transport check too.
        let mut r = acc.remove_member(&a.owner, &id, &m.user_id, "left", 4_000).unwrap();
        assert!(sign_revocation(&alice, "example-app", &a, &mut r.clone()).is_err());
        sign_revocation(&owner, "example-app", &a, &mut r).unwrap();
        let revs = revocations(&a, &[r]).unwrap();
        assert!(caller_from_presented(&WEIRDNET, &presented, &peer, "example-app", &a, &revs, 5_000).is_err());
        // And the stored revocation alone stops the authorizer.
        assert!(az.authorize(&Request { caller: &caller, account: &id, perm: "read", now_ms: 5_000 }).is_err());
    }
}
