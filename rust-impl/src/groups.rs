//! WIRE_FORMAT §4.6: group state (0x03) and group text (0x04), and the receive rules.

use std::collections::{BTreeMap, HashMap};

use crate::first_contact::{decode_name_field, encode_name_field};
use crate::primitives::{blake2b, schnorr_sign, schnorr_verify, to32, Key32};
use crate::session::MAX_CONTENT;
use crate::Error;

pub const MAX_MEMBERS: usize = 4;
pub const TEXT_HEADER_LEN: usize = 1 + 16 + 4 + 16;
pub const MAX_GROUP_TEXT: usize = MAX_CONTENT - TEXT_HEADER_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub owner_pub: Key32,
    pub id_x25519_pub: Key32,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupState {
    pub group_id: [u8; 16],
    pub epoch: u32,
    pub admin_owner_pub: Key32,
    pub members: Vec<Member>,
    pub signature: [u8; 64],
}

fn state_unsigned(group_id: &[u8; 16], epoch: u32, admin: &Key32, members: &[Member]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::with_capacity(54 + 85 * members.len());
    v.push(1);
    v.extend_from_slice(group_id);
    v.extend_from_slice(&epoch.to_be_bytes());
    v.extend_from_slice(admin);
    v.push(members.len() as u8);
    for m in members {
        v.extend_from_slice(&m.owner_pub);
        v.extend_from_slice(&m.id_x25519_pub);
        v.extend_from_slice(&encode_name_field(&m.name)?);
    }
    Ok(v)
}

fn state_digest(unsigned: &[u8]) -> Key32 {
    blake2b(&[b"kasveil/v1/group-state", unsigned])
}

impl GroupState {
    pub fn create(admin_sk: &Key32, admin_pub: Key32, group_id: [u8; 16], epoch: u32, members: Vec<Member>, aux: &Key32) -> Result<Self, Error> {
        if members.is_empty() || members.len() > MAX_MEMBERS {
            return Err(Error::Malformed);
        }
        let u = state_unsigned(&group_id, epoch, &admin_pub, &members)?;
        let signature = schnorr_sign(admin_sk, &state_digest(&u), aux)?;
        Ok(GroupState { group_id, epoch, admin_owner_pub: admin_pub, members, signature })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = state_unsigned(&self.group_id, self.epoch, &self.admin_owner_pub, &self.members).expect("valid names");
        v.extend_from_slice(&self.signature);
        v
    }

    /// Parses and checks everything that doesn't need receiver context: layout, 1–4 members,
    /// name fields, unique `ownerPub`, admin among the members, signature.
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 118 || b[0] != 1 {
            return Err(Error::Malformed);
        }
        let n = b[53] as usize;
        if !(1..=MAX_MEMBERS).contains(&n) || b.len() != 118 + 85 * n {
            return Err(Error::Malformed);
        }
        let mut members = Vec::with_capacity(n);
        for i in 0..n {
            let o = 54 + 85 * i;
            members.push(Member { owner_pub: to32(&b[o..]), id_x25519_pub: to32(&b[o + 32..]), name: decode_name_field(&b[o + 64..o + 85])? });
        }
        let admin = to32(&b[21..]);
        for (i, m) in members.iter().enumerate() {
            if members[..i].iter().any(|x| x.owner_pub == m.owner_pub) {
                return Err(Error::Malformed);
            }
        }
        if !members.iter().any(|m| m.owner_pub == admin) {
            return Err(Error::Malformed);
        }
        let sig_off = b.len() - 64;
        if !schnorr_verify(&admin, &state_digest(&b[..sig_off]), &b[sig_off..]) {
            return Err(Error::BadSignature);
        }
        Ok(GroupState {
            group_id: b[1..17].try_into().unwrap(),
            epoch: u32::from_be_bytes(b[17..21].try_into().unwrap()),
            admin_owner_pub: admin,
            members,
            signature: b[sig_off..].try_into().unwrap(),
        })
    }

    pub fn lists(&self, owner: &Key32) -> bool {
        self.members.iter().any(|m| &m.owner_pub == owner)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupText {
    pub group_id: [u8; 16],
    pub epoch: u32,
    pub msg_id: [u8; 16],
    pub text: Vec<u8>,
}

impl GroupText {
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.text.len() > MAX_GROUP_TEXT {
            return Err(Error::TooLong);
        }
        let mut v = Vec::with_capacity(TEXT_HEADER_LEN + self.text.len());
        v.push(1);
        v.extend_from_slice(&self.group_id);
        v.extend_from_slice(&self.epoch.to_be_bytes());
        v.extend_from_slice(&self.msg_id);
        v.extend_from_slice(&self.text);
        Ok(v)
    }

    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < TEXT_HEADER_LEN || b[0] != 1 {
            return Err(Error::Malformed);
        }
        Ok(GroupText {
            group_id: b[1..17].try_into().unwrap(),
            epoch: u32::from_be_bytes(b[17..21].try_into().unwrap()),
            msg_id: b[21..37].try_into().unwrap(),
            text: b[37..].to_vec(),
        })
    }

    /// Displayed text: invalid UTF-8 is shown with U+FFFD replacement characters.
    pub fn display(&self) -> String {
        String::from_utf8_lossy(&self.text).into_owned()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateEvent {
    Joined { epoch: u32 },
    /// Includes a re-add ("a re-add is an update").
    Updated { epoch: u32 },
    Removed { epoch: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextOutcome {
    Accepted { text: String, epoch: u32, older_epoch: bool, sender: Key32, msg_id: [u8; 16] },
    Pending,
}

#[derive(Clone, Debug)]
struct Group {
    admin: Key32,
    current_epoch: u32,
    /// Every accepted state, by epoch.
    states: BTreeMap<u32, GroupState>,
}

/// One receiver's view of its groups. "Rejected" means the content is discarded; the
/// ratchet message carrying it has already counted as received (§7).
pub struct GroupReceiver {
    pub me: Key32,
    groups: HashMap<[u8; 16], Group>,
    held: Vec<(Key32, Vec<u8>)>,
}

impl GroupReceiver {
    pub fn new(me: Key32) -> Self {
        GroupReceiver { me, groups: HashMap::new(), held: Vec::new() }
    }

    /// A group state that arrived over the pairwise session with `from` (the peer's owner key).
    /// Returns the event and the outcomes of held texts retried after it.
    pub fn receive_state(&mut self, from: &Key32, content: &[u8]) -> Result<(StateEvent, Vec<Result<TextOutcome, Error>>), Error> {
        let st = GroupState::parse(content)?;
        if &st.admin_owner_pub != from {
            return Err(Error::WrongOwner);
        }
        let lists_me = st.lists(&self.me);
        let event = match self.groups.get_mut(&st.group_id) {
            Some(g) => {
                if g.admin != st.admin_owner_pub || st.epoch <= g.current_epoch {
                    return Err(Error::State);
                }
                let epoch = st.epoch;
                g.current_epoch = epoch;
                g.states.insert(epoch, st);
                if lists_me {
                    StateEvent::Updated { epoch }
                } else {
                    StateEvent::Removed { epoch }
                }
            }
            None => {
                if !lists_me {
                    return Err(Error::State);
                }
                let epoch = st.epoch;
                let mut states = BTreeMap::new();
                let gid = st.group_id;
                let admin = st.admin_owner_pub;
                states.insert(epoch, st);
                self.groups.insert(gid, Group { admin, current_epoch: epoch, states });
                StateEvent::Joined { epoch }
            }
        };
        let held = std::mem::take(&mut self.held);
        let retried = held.into_iter().map(|(f, c)| self.receive_text(&f, &c)).collect();
        Ok((event, retried))
    }

    /// A group text that arrived over the pairwise session with `from`.
    pub fn receive_text(&mut self, from: &Key32, content: &[u8]) -> Result<TextOutcome, Error> {
        let t = GroupText::parse(content)?;
        let Some(g) = self.groups.get(&t.group_id) else {
            self.held.push((*from, content.to_vec()));
            return Ok(TextOutcome::Pending);
        };
        if t.epoch > g.current_epoch {
            self.held.push((*from, content.to_vec()));
            return Ok(TextOutcome::Pending);
        }
        let st = g.states.get(&t.epoch).ok_or(Error::State)?;
        if !st.lists(from) || !st.lists(&self.me) {
            return Err(Error::State);
        }
        Ok(TextOutcome::Accepted { text: t.display(), epoch: t.epoch, older_epoch: t.epoch < g.current_epoch, sender: *from, msg_id: t.msg_id })
    }
}
