// Kaspaveil wire-format constants (protocol version 1). See docs/WIRE_FORMAT.md.

export const VERSION = 1;
export const PAYLOAD_LEN = 1536;
export const TAG_LEN = 16;
export const FIELD_LEN = 32;
export const AEAD_TAG_LEN = 16;
export const MLKEM_PK_LEN = 1184;
export const MLKEM_CT_LEN = 1088;

// Ongoing (ratchet) message: ver | tag | random32 | header ct | body ct
export const HEADER_PT_LEN = 48;
export const HEADER_CT_LEN = HEADER_PT_LEN + AEAD_TAG_LEN;
export const BODY_CT_LEN = PAYLOAD_LEN - 1 - TAG_LEN - FIELD_LEN - HEADER_CT_LEN; // 1423
export const BODY_PT_LEN = BODY_CT_LEN - AEAD_TAG_LEN; // 1407

// First contact: ver | tag | ephemeral32 | ML-KEM ct | sealed ct
export const FC_SEALED_CT_LEN = PAYLOAD_LEN - 1 - TAG_LEN - FIELD_LEN - MLKEM_CT_LEN; // 399
export const FC_SEALED_PT_LEN = FC_SEALED_CT_LEN - AEAD_TAG_LEN; // 383
export const NAME_FIELD_LEN = 21; // 1-byte length + up to 20 bytes
export const FC_INNER_CT_LEN = FC_SEALED_PT_LEN - 1 - NAME_FIELD_LEN - 32 - 32 - 4 - 32; // 261
export const FC_INNER_PT_LEN = FC_INNER_CT_LEN - AEAD_TAG_LEN; // 245

// Body content kinds (first byte of every decrypted body)
export const KIND_TEXT = 0x01;
export const KIND_GROUP_STATE = 0x03;
export const KIND_GROUP_TEXT = 0x04;
export const KIND_KEM_STEP = 0x05;
export const KIND_SETTINGS = 0x06;
export const KIND_NOTICE = 0x07;
export const KIND_NAME = 0x08;

// Sealed first-contact record type
export const FC_TYPE = 0x01;

export const MAX_TEXT_FIRST_CONTACT = FC_INNER_PT_LEN - 3; // kind + u16 length
export const MAX_TEXT = BODY_PT_LEN - 3;
export const MAX_SKIP = 1000;
export const TAG_WINDOW = 64;

// Kaspa user lane for Kaspaveil: "KVL" 0x01 followed by 16 zero bytes.
export const LANE_ID = new Uint8Array([0x4b, 0x56, 0x4c, 0x01, ...new Array(16).fill(0)]);
