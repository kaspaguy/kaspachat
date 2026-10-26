//! Rules the vectors don't reach, exercised with real randomness: skipped-key limit and
//! expiry, the crossing-first-contact rule, previous prekeys, size limits, KEM re-offers and
//! late messages across the tag switch, group re-adds, settings replacement, bundle devices.

use kaspaveil_wire::bundle::{current_bundle, Bundle};
use kaspaveil_wire::first_contact::{self, open_first_contact, PeerSessions, Recipient, RegistryEntry, Sender};
use kaspaveil_wire::groups::{GroupReceiver, GroupState, GroupText, Member, StateEvent, TextOutcome};
use kaspaveil_wire::keys::{identity_from_seed, prekey, Identity, Prekey};
use kaspaveil_wire::random::{OsRandom, RandomSource};
use kaspaveil_wire::session::{Session, SKIPPED_KEY_LIFETIME};
use kaspaveil_wire::settings::{self, Prefs};
use kaspaveil_wire::{Error, PAYLOAD_LEN};

struct Party {
    id: Identity,
    name: String,
    prekeys: Vec<Prekey>,
    bundle: Bundle,
}

fn party(fill: u8, name: &str, spk: u32) -> Party {
    let id = identity_from_seed([fill; 64]);
    let prekeys: Vec<Prekey> = (1..=spk).rev().map(|n| prekey(&id.seed, n)).collect();
    let cur = &prekeys[0];
    let bundle = Bundle::create(
        &id.owner_sk,
        id.owner_pub,
        id.id_x25519_pub,
        cur.spk_id,
        cur.x25519_pub,
        cur.mlkem_pub.clone(),
        1_780_000_000,
        vec![],
        &OsRandom.schnorr_aux(),
    )
    .unwrap();
    Party { id, name: name.into(), prekeys, bundle }
}

fn registry(parties: &[&Party]) -> impl Fn(&str) -> Option<RegistryEntry> {
    let entries: Vec<(String, RegistryEntry)> =
        parties.iter().map(|p| (p.name.clone(), RegistryEntry { owner_pub: p.id.owner_pub, id_x25519_pub: p.id.id_x25519_pub })).collect();
    move |n: &str| entries.iter().find(|(k, _)| k == n).map(|(_, e)| e.clone())
}

fn sender(p: &Party) -> Sender<'_> {
    Sender { owner_pub: p.id.owner_pub, id_x25519_sk: p.id.id_x25519_sk, id_x25519_pub: p.id.id_x25519_pub, name: &p.name }
}

fn recipient(p: &Party) -> Recipient<'_> {
    Recipient { id_x25519_sk: p.id.id_x25519_sk, id_x25519_pub: p.id.id_x25519_pub, prekeys: &p.prekeys }
}

fn contact(from: &Party, to: &Party, to_bundle: &Bundle) -> (Session, Session, [u8; 16]) {
    let out = first_contact::send(&sender(from), to_bundle, 1, b"hi", &mut OsRandom).unwrap();
    let reg = registry(&[from, to]);
    let opened = open_first_contact(&recipient(to), &reg, &out.payload, &mut OsRandom).unwrap();
    assert_eq!(opened.from, from.name);
    assert_eq!(opened.content, b"hi");
    (out.session, opened.session, out.tag)
}

fn pair() -> (Session, Session) {
    let a = party(1, "alice-21", 1);
    let b = party(2, "bob-22", 1);
    let (s_a, s_b, _) = contact(&a, &b, &b.bundle);
    (s_a, s_b)
}

fn send(s: &mut Session, text: &[u8]) -> Vec<u8> {
    s.encrypt(1, text, &mut OsRandom).unwrap()
}

fn recv(s: &mut Session, p: &[u8]) -> Result<Vec<u8>, Error> {
    s.decrypt(p, &mut OsRandom, 0).map(|r| r.content)
}

#[test]
fn conversation_no_repeated_clear_fields() {
    let (mut a, mut b) = pair();
    let mut tags = std::collections::HashSet::new();
    let mut fields = std::collections::HashSet::new();
    for i in 0..21u8 {
        let (from, to) = if i % 3 == 2 { (&mut b, &mut a) } else { (&mut a, &mut b) };
        let p = send(from, &[i]);
        assert_eq!(p.len(), PAYLOAD_LEN);
        assert!(tags.insert(p[1..17].to_vec()), "tag repeated");
        assert!(fields.insert(p[17..49].to_vec()), "random field repeated");
        assert_eq!(recv(to, &p).unwrap(), vec![i]);
    }
}

#[test]
fn size_limits() {
    let a = party(1, "alice-21", 1);
    let b = party(2, "bob-22", 1);
    assert!(first_contact::send(&sender(&a), &b.bundle, 1, &[b'x'; 242], &mut OsRandom).is_ok());
    assert_eq!(first_contact::send(&sender(&a), &b.bundle, 1, &[b'x'; 243], &mut OsRandom).unwrap_err(), Error::TooLong);
    assert!(first_contact::send(&sender(&a), &b.bundle, 5, b"x", &mut OsRandom).is_err(), "kind 0x05 can't open a session");
    let (mut sa, mut sb) = pair();
    let p = sa.encrypt(1, &[7; 1404], &mut OsRandom).unwrap();
    assert_eq!(recv(&mut sb, &p).unwrap(), vec![7; 1404]);
    assert_eq!(sa.encrypt(1, &[7; 1405], &mut OsRandom).unwrap_err(), Error::TooLong);
}

#[test]
fn unknown_kinds_are_received() {
    let (mut a, mut b) = pair();
    for kind in [0x00u8, 0x02, 0x07, 0xff] {
        let p = a.encrypt(kind, b"future", &mut OsRandom).unwrap();
        let r = b.decrypt(&p, &mut OsRandom, 0).unwrap();
        assert_eq!(r.kind, kind);
    }
    assert_eq!(b.tag_in, 4, "the tag window moved on");
}

#[test]
fn first_contact_on_previous_prekey() {
    let a = party(1, "alice-21", 1);
    let old_bob = party(2, "bob-22", 1);
    let bob_rotated = party(2, "bob-22", 2);
    assert_eq!(bob_rotated.prekeys[0].spk_id, 2);
    assert_eq!(bob_rotated.prekeys[1].spk_id, 1);
    // Alice used Bob's older bundle (prekey 1); Bob has rotated to 2 and still opens it.
    let (_, _, _) = contact(&a, &bob_rotated, &old_bob.bundle);
    // A prekey two rotations old is not tried.
    let bob_twice = party(2, "bob-22", 3);
    let bob_twice_trimmed = Party { prekeys: bob_twice.prekeys[..2].to_vec(), ..bob_twice };
    let out = first_contact::send(&sender(&a), &old_bob.bundle, 1, b"hi", &mut OsRandom).unwrap();
    let reg = registry(&[&a, &bob_twice_trimmed]);
    assert!(open_first_contact(&recipient(&bob_twice_trimmed), &reg, &out.payload, &mut OsRandom).is_err());
}

#[test]
fn impersonation_and_wrong_recipient_rejected() {
    let a = party(1, "alice-21", 1);
    let b = party(2, "bob-22", 1);
    let eve = party(3, "eve-23", 1);
    let out = first_contact::send(&sender(&a), &b.bundle, 1, b"hi", &mut OsRandom).unwrap();
    // Eve claims to be alice-21 with her own keys: the registry doesn't agree.
    let fake = Sender { name: "alice-21", ..sender(&eve) };
    let forged = first_contact::send(&fake, &b.bundle, 1, b"hi", &mut OsRandom).unwrap();
    let reg = registry(&[&a, &b]);
    assert_eq!(open_first_contact(&recipient(&b), &reg, &forged.payload, &mut OsRandom).unwrap_err(), Error::FirstContact);
    assert!(open_first_contact(&recipient(&eve), &reg, &out.payload, &mut OsRandom).is_err());
    let mut tampered = out.payload.clone();
    tampered[1500] ^= 1;
    assert!(open_first_contact(&recipient(&b), &reg, &tampered, &mut OsRandom).is_err());
}

#[test]
fn skipped_key_limit_is_per_chain_per_message() {
    let (mut a, b) = pair();
    let payloads: Vec<Vec<u8>> = (0..1002).map(|i| send(&mut a, format!("{i}").as_bytes())).collect();
    // Tag index i carries header N = i + 1 (the first contact was N = 0). Bob's nr is 1.
    // A receiver that widened its window to reach index 1001 would need 1,001 skipped keys: rejected.
    let mut bob = b.clone();
    bob.tag_in = 1001;
    let before = bob.clone();
    assert_eq!(bob.decrypt(&payloads[1001], &mut OsRandom, 0).unwrap_err(), Error::TooManySkipped);
    assert_eq!(bob, before);
    // Exactly 1,000 is allowed.
    let mut bob = b.clone();
    bob.tag_in = 1000;
    assert_eq!(recv(&mut bob, &payloads[1000]).unwrap(), b"1000");
    assert_eq!(bob.skipped.len(), 1000);
    // Beyond the 64-index window a conforming receiver doesn't even see the tag.
    let mut bob = b.clone();
    assert_eq!(bob.decrypt(&payloads[64], &mut OsRandom, 0).unwrap_err(), Error::UnknownTag);
    assert!(recv(&mut bob, &payloads[63]).is_ok());
}

#[test]
fn skipped_keys_expire_after_seven_days() {
    let (mut a, b) = pair();
    let m0 = send(&mut a, b"zero");
    let m1 = send(&mut a, b"one");
    let t0 = 1_000_000;
    let mut bob = b.clone();
    bob.decrypt(&m1, &mut OsRandom, t0).unwrap();
    assert_eq!(bob.skipped.len(), 1);
    assert_eq!(bob.skipped[0].stored_at, t0);
    let mut early = bob.clone();
    assert_eq!(early.decrypt(&m0, &mut OsRandom, t0 + SKIPPED_KEY_LIFETIME - 1).unwrap().content, b"zero");
    let mut late = bob.clone();
    assert!(late.decrypt(&m0, &mut OsRandom, t0 + SKIPPED_KEY_LIFETIME).is_err());
    assert!(late.skipped.is_empty(), "the expired key was deleted");
}

#[test]
fn crossing_first_contacts() {
    let a = party(1, "alice-21", 1);
    let b = party(2, "bob-22", 1);
    let (a_sent, b_recv, tag_ab) = contact(&a, &b, &b.bundle);
    let (b_sent, a_recv, tag_ba) = contact(&b, &a, &a.bundle);
    // Each side learns of the crossing. Both must pick the same pair.
    let mut alice = PeerSessions::new(a_sent, tag_ab);
    alice.on_first_contact_received(a_recv, tag_ba, 0);
    let mut bob = PeerSessions::new(b_sent, tag_ba);
    // Bob had an in-flight message on the session he sent, before learning of the crossing.
    let in_flight = send(&mut bob.primary, b"sent before I knew");
    bob.on_first_contact_received(b_recv, tag_ab, 0);
    assert_eq!(alice.primary_fc_tag, bob.primary_fc_tag);
    assert_eq!(alice.primary_fc_tag, *std::cmp::min(&tag_ab, &tag_ba));
    // The kept pair works both ways.
    let p = send(&mut alice.primary, b"kept");
    assert_eq!(bob.receive(&p, &mut OsRandom, 10).unwrap().content, b"kept");
    let p = send(&mut bob.primary, b"kept too");
    assert_eq!(alice.receive(&p, &mut OsRandom, 10).unwrap().content, b"kept too");
    // Bob's in-flight message: received on whichever session it belongs to.
    assert_eq!(alice.receive(&in_flight, &mut OsRandom, 20).unwrap().content, b"sent before I knew");
    // After the 7-day window the losing session is gone.
    alice.expire(7 * 24 * 3600);
    assert!(alice.receive_only.is_none());
}

#[test]
fn crossing_losing_session_never_answers_kem() {
    let a = party(1, "alice-21", 1);
    let b = party(2, "bob-22", 1);
    let (mut a_sent, b_recv, tag_ab) = contact(&a, &b, &b.bundle);
    let (b_sent, a_recv, tag_ba) = contact(&b, &a, &a.bundle);
    let mut bob = PeerSessions::new(b_sent, tag_ba);
    bob.add_crossing(b_recv, tag_ab, 0);
    // Make Alice's sent session the loser from Bob's point of view if needed.
    if tag_ab < tag_ba {
        // Bob keeps b_recv (primary); an offer on it is answered.
        let offer = a_sent.kem_offer(OsRandom.mlkem_keygen_seed(), 0).unwrap();
        let p = a_sent.encrypt(5, &offer, &mut OsRandom).unwrap();
        assert!(bob.receive(&p, &mut OsRandom, 0).unwrap().kem_answer.is_some());
    } else {
        // Bob's primary is b_sent; an offer arriving on the receive-only b_recv is not answered.
        let offer = a_sent.kem_offer(OsRandom.mlkem_keygen_seed(), 0).unwrap();
        let p = a_sent.encrypt(5, &offer, &mut OsRandom).unwrap();
        let r = bob.receive(&p, &mut OsRandom, 0).unwrap();
        assert_eq!(r.kind, 5);
        assert!(r.kem_answer.is_none());
        assert!(bob.receive_only.as_ref().unwrap().0.pq_secret.is_none());
    }
    let _ = a_recv;
}

/// Runs messages until both sides have mixed epoch `e`.
fn finish_step(a: &mut Session, b: &mut Session, e: u32) {
    for _ in 0..4 {
        let p = send(b, b"b");
        recv(a, &p).unwrap();
        let p = send(a, b"a");
        recv(b, &p).unwrap();
    }
    assert_eq!((a.pq_epoch, b.pq_epoch), (e, e));
    assert!(a.pq_secret.is_none() && b.pq_secret.is_none());
    assert!(a.tag_key_in_next.is_none() && b.tag_key_in_next.is_none());
}

#[test]
fn kem_step_real_randomness_and_second_step() {
    let (mut a, mut b) = pair();
    let old_out = a.tag_key_out;
    let offer = a.kem_offer(OsRandom.mlkem_keygen_seed(), 0).unwrap();
    let p = a.encrypt(5, &offer, &mut OsRandom).unwrap();
    let ans = b.decrypt(&p, &mut OsRandom, 0).unwrap().kem_answer.unwrap();
    let p = b.encrypt(5, &ans, &mut OsRandom).unwrap();
    assert!(b.kem_offer(OsRandom.mlkem_keygen_seed(), 0).is_err(), "never offers while holding SS");
    recv(&mut a, &p).unwrap();
    finish_step(&mut a, &mut b, 1);
    assert_ne!(a.tag_key_out, old_out);
    // Bob starts the next step.
    let offer = b.kem_offer(OsRandom.mlkem_keygen_seed(), 0).unwrap();
    let p = b.encrypt(5, &offer, &mut OsRandom).unwrap();
    let ans = a.decrypt(&p, &mut OsRandom, 0).unwrap().kem_answer.unwrap();
    let p = a.encrypt(5, &ans, &mut OsRandom).unwrap();
    recv(&mut b, &p).unwrap();
    finish_step(&mut a, &mut b, 2);
}

#[test]
fn kem_lost_answer_and_reoffer() {
    let (mut a, mut b) = pair();
    let offer1 = a.kem_offer(OsRandom.mlkem_keygen_seed(), 0).unwrap();
    let p = a.encrypt(5, &offer1, &mut OsRandom).unwrap();
    let ans1 = b.decrypt(&p, &mut OsRandom, 0).unwrap().kem_answer.unwrap();
    let lost = b.encrypt(5, &ans1, &mut OsRandom).unwrap();
    // The answer is lost; Alice re-offers, replacing her offer.
    let offer2 = a.kem_offer(OsRandom.mlkem_keygen_seed(), 0).unwrap();
    let p = a.encrypt(5, &offer2, &mut OsRandom).unwrap();
    let ans2 = b.decrypt(&p, &mut OsRandom, 0).unwrap().kem_answer.expect("answered again");
    let p2 = b.encrypt(5, &ans2, &mut OsRandom).unwrap();
    // The lost answer turns up late: it answers a replaced offer and is ignored (still received).
    recv(&mut a, &lost).unwrap();
    assert!(a.pq_offer.is_some() && a.pq_secret.is_none());
    recv(&mut a, &p2).unwrap();
    assert!(a.pq_secret.as_ref().unwrap().mix_on_send);
    finish_step(&mut a, &mut b, 1);
}

#[test]
fn kem_late_message_across_tag_switch() {
    let (mut a, mut b) = pair();
    let offer = a.kem_offer(OsRandom.mlkem_keygen_seed(), 0).unwrap();
    let p = a.encrypt(5, &offer, &mut OsRandom).unwrap();
    let ans = b.decrypt(&p, &mut OsRandom, 0).unwrap().kem_answer.unwrap();
    let p = b.encrypt(5, &ans, &mut OsRandom).unwrap();
    recv(&mut a, &p).unwrap();
    // Alice sends one message on her old tag chain that is delayed, then one that arrives.
    let late = send(&mut a, b"late, old tag chain");
    let m2 = send(&mut a, b"on time");
    recv(&mut b, &m2).unwrap();
    // Bob's new ratchet key (his DH step on m2) makes Alice mix.
    let p = send(&mut b, b"b1");
    recv(&mut a, &p).unwrap();
    assert_eq!(a.pq_epoch, 1);
    let first_rekeyed = send(&mut a, b"first on the re-keyed chain");
    recv(&mut b, &first_rekeyed).unwrap();
    assert_eq!(b.pq_epoch, 1);
    assert!(b.previous_in.is_some());
    // The late message arrives on the previous chain, from its skipped key.
    assert_eq!(recv(&mut b, &late).unwrap(), b"late, old tag chain");
    // A replay is rejected: its index is no longer watched.
    assert_eq!(b.decrypt(&late, &mut OsRandom, 0).unwrap_err(), Error::UnknownTag);
    finish_step(&mut a, &mut b, 1);
}

#[test]
fn kem_due_policy() {
    let (mut a, mut b) = pair();
    assert!(!a.kem_due(0));
    for _ in 0..25 {
        let p = send(&mut a, b"x");
        recv(&mut b, &p).unwrap();
        let p = send(&mut b, b"y");
        recv(&mut a, &p).unwrap();
    }
    assert!(a.kem_due(0), "50 messages sent and received");
    let (a2, _) = pair();
    assert!(a2.kem_due(24 * 3600), "24 hours since the session started");
}

#[test]
fn pq_epoch_receive_rule_rejects_jumps() {
    let (mut a, mut b) = pair();
    // Alice claims epoch 1 without any step: Bob's DH step rejects it.
    let p = send(&mut b, b"b");
    recv(&mut a, &p).unwrap();
    a.pq_epoch = 1;
    let p = send(&mut a, b"jump");
    let before = b.clone();
    assert_eq!(b.decrypt(&p, &mut OsRandom, 0).unwrap_err(), Error::PqEpoch);
    assert_eq!(b, before);
}

fn member(p: &Party) -> Member {
    Member { owner_pub: p.id.owner_pub, id_x25519_pub: p.id.id_x25519_pub, name: p.name.clone() }
}

#[test]
fn group_removal_and_readd() {
    let a = party(1, "alice-21", 1);
    let b = party(2, "bob-22", 1);
    let c = party(3, "carol-23", 1);
    let gid = [9u8; 16];
    let st = |epoch: u32, ms: Vec<Member>| {
        GroupState::create(&a.id.owner_sk, a.id.owner_pub, gid, epoch, ms, &OsRandom.schnorr_aux()).unwrap().to_bytes()
    };
    let text = |epoch: u32, t: &[u8]| GroupText { group_id: gid, epoch, msg_id: [epoch as u8; 16], text: t.to_vec() }.to_bytes().unwrap();
    let mut rx = GroupReceiver::new(b.id.owner_pub);
    // A text for a group not known yet is held, and retried after the state.
    assert_eq!(rx.receive_text(&c.id.owner_pub, &text(1, b"early")).unwrap(), TextOutcome::Pending);
    let (ev, retried) = rx.receive_state(&a.id.owner_pub, &st(1, vec![member(&a), member(&b), member(&c)])).unwrap();
    assert_eq!(ev, StateEvent::Joined { epoch: 1 });
    assert!(matches!(&retried[..], [Ok(TextOutcome::Accepted { .. })]));
    assert_eq!(rx.receive_state(&a.id.owner_pub, &st(2, vec![member(&a), member(&c)])).unwrap().0, StateEvent::Removed { epoch: 2 });
    assert!(rx.receive_text(&c.id.owner_pub, &text(2, b"after removal")).is_err());
    assert_eq!(rx.receive_state(&a.id.owner_pub, &st(3, vec![member(&a), member(&b)])).unwrap().0, StateEvent::Updated { epoch: 3 });
    assert!(rx.receive_text(&c.id.owner_pub, &text(3, b"carol removed")).is_err());
    assert!(rx.receive_text(&a.id.owner_pub, &text(2, b"removal epoch")).is_err(), "epoch 2 doesn't list the receiver");
    assert!(matches!(rx.receive_text(&a.id.owner_pub, &text(3, b"back")).unwrap(), TextOutcome::Accepted { older_epoch: false, .. }));
    assert!(matches!(rx.receive_text(&a.id.owner_pub, &text(1, b"old")).unwrap(), TextOutcome::Accepted { older_epoch: true, .. }));
    // Invalid UTF-8 is shown with replacement characters.
    match rx.receive_text(&a.id.owner_pub, &text(3, &[0x66, 0xff, 0x6f])).unwrap() {
        TextOutcome::Accepted { text, .. } => assert_eq!(text, "f\u{fffd}o"),
        o => panic!("{o:?}"),
    }
    // Duplicate owner keys and a missing admin are invalid states.
    assert!(GroupState::parse(&st(4, vec![member(&a), member(&b), member(&b)])).is_err());
    assert!(GroupState::parse(&st(4, vec![member(&b)])).is_err());
    // A state not listing us, for an unknown group, is not joined.
    let mut rx_c = GroupReceiver::new(c.id.owner_pub);
    assert!(rx_c.receive_state(&a.id.owner_pub, &st(5, vec![member(&a), member(&b)])).is_err());
}

#[test]
fn settings_replacement_rule() {
    let p = |epoch, off| Prefs { version: 1, epoch, group_id: None, timer_off: off, screenshot_protection: false };
    let mut slot = None;
    assert!(settings::update(&mut slot, p(100, true)), "the first preferences are kept whatever their epoch");
    assert!(!settings::update(&mut slot, p(100, false)), "equal epoch ignored");
    assert!(!settings::update(&mut slot, p(99, false)), "lower epoch ignored");
    assert!(settings::update(&mut slot, p(101, false)));
    assert_eq!(slot, Some(p(101, false)));
}

#[test]
fn bundle_devices_and_current_bundle() {
    let b = party(2, "bob-22", 1);
    let pk = &b.prekeys[0];
    let mk = |created: u64, spk: u32, devices: Vec<[u8; 32]>| {
        Bundle::create(&b.id.owner_sk, b.id.owner_pub, b.id.id_x25519_pub, spk, pk.x25519_pub, pk.mlkem_pub.clone(), created, devices, &[0; 32])
            .unwrap()
    };
    let with_devices = mk(10, 1, vec![[1; 32], [2; 32]]);
    let bytes = with_devices.to_bytes();
    assert_eq!(bytes.len(), 1358 + 64);
    assert_eq!(Bundle::accept(&bytes, &b.id.owner_pub).unwrap().devices.len(), 2);
    // A trailing byte makes a standalone bundle invalid; nDevices > 4 is rejected.
    let mut long = bytes.clone();
    long.push(0);
    assert!(Bundle::accept(&long, &b.id.owner_pub).is_err());
    let mut too_many = mk(10, 1, vec![]).to_bytes();
    too_many[1293] = 5;
    too_many.extend(vec![0u8; 5 * 32]);
    assert!(Bundle::accept(&too_many, &b.id.owner_pub).is_err());
    let now = 1_000_000;
    let list = vec![mk(now - 10, 3, vec![]), mk(now - 10, 4, vec![]), mk(now - 20, 9, vec![]), mk(now + 24 * 3600 + 1, 5, vec![])];
    assert_eq!(current_bundle(&list, now).unwrap().spk_id, 4);
}

#[test]
fn tag_window_is_64_unreceived_indices() {
    let (mut a, b) = pair();
    let ps: Vec<Vec<u8>> = (0..80).map(|i| send(&mut a, &[i as u8])).collect();
    let mut bob = b.clone();
    // Receive 1..=10 out of order (index 0 missing): the window then covers index 0 and 11..=73.
    for p in &ps[1..=10] {
        recv(&mut bob, p).unwrap();
    }
    assert_eq!((bob.tag_in, bob.seen_in.len()), (0, 10));
    assert_eq!(bob.watched_tags().len(), 64);
    assert!(recv(&mut bob.clone(), &ps[73]).is_ok());
    assert_eq!(bob.clone().decrypt(&ps[74], &mut OsRandom, 0).unwrap_err(), Error::UnknownTag);
}

#[test]
fn recontact_after_restore_replaces_the_old_session() {
    let a = party(1, "alice-21", 1);
    let b = party(2, "bob-22", 1);
    let (mut a_old, b_old, tag_old) = contact(&a, &b, &b.bundle);
    let mut bob = PeerSessions::new(b_old, tag_old);
    // An established conversation.
    let p = send(&mut bob.primary, b"hello");
    recv(&mut a_old, &p).unwrap();
    // Alice restores from her phrase (sessions can't be restored) and contacts Bob again.
    let (mut a_new, b_new, tag_new) = contact(&a, &b, &b.bundle);
    bob.on_first_contact_received(b_new, tag_new, 0);
    assert_eq!(bob.primary_fc_tag, tag_new, "whatever the tags, the new session is used");
    let p = send(&mut bob.primary, b"to the restored alice");
    assert_eq!(recv(&mut a_new, &p).unwrap(), b"to the restored alice");
}
