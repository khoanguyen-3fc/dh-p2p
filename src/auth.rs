//! Device authentication for the P2P channel request.
//!
//! Devices with a password set answer `/device/{serial}/p2p-channel` with
//! `403 DevPwd_InvalidSalt` unless the request carries a signature derived from
//! the credentials and a per-device salt. Without this the handshake reaches
//! the relay and then stops, which is what an unauthenticated client sees.
//!
//! Ported from the Python implementation in this repository, which already
//! implements the scheme; the constants and the exact string forms below are
//! what the device checks, so they are reproduced rather than reinvented.

use aes::Aes256;
use base64::Engine;
use hmac::{Hmac, Mac};
use md5::Md5;
use ofb::cipher::{KeyIvInit, StreamCipher};
use ofb::Ofb;
use sha2::{Digest as Sha2Digest, Sha256};

type AesOfb = Ofb<Aes256>;

/// Key and IV the cloud uses for the `<Info>` payload of `/info/device/{serial}`.
/// Fixed across every device rather than derived per session.
const INFO_KEY: &[u8; 32] = b"kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf";
const INFO_IV: &[u8; 16] = b"MydvJw*Iw1w&i^kk";
/// IV for the per-session key that encrypts the local address.
const IV: &[u8; 16] = b"2z52*lk9o6HRyJrf";
/// Iterations the device expects when deriving that key. Not a tunable — the
/// far end derives the same key and a different count simply fails to match.
const PBKDF2_ROUNDS: u32 = 20_000;

/// Decrypt the `<Info>` payload and return the device's salt.
///
/// Returns an empty string when there is no payload or it cannot be read:
/// firmware that reports no info expects no salt, and the caller then signs
/// without one rather than giving up.
pub fn device_salt(info: &str) -> String {
    if info.is_empty() {
        return String::new();
    }
    let Ok(mut raw) = base64::engine::general_purpose::STANDARD.decode(info) else {
        return String::new();
    };
    AesOfb::new(INFO_KEY.into(), INFO_IV.into()).apply_keystream(&mut raw);

    let Ok(text) = String::from_utf8(raw) else {
        return String::new();
    };
    // Picked out by hand rather than with a JSON parser: this is the only field
    // wanted, and the payload is not always valid JSON to its last byte.
    let Some(start) = text.find("\"randsalt\"") else {
        return String::new();
    };
    let rest = &text[start + "\"randsalt\"".len()..];
    let Some(open) = rest.find('"') else {
        return String::new();
    };
    let tail = &rest[open + 1..];
    match tail.find('"') {
        Some(end) => tail[..end].to_string(),
        None => String::new(),
    }
}

/// The shared secret both ends derive from the credentials and the salt.
pub fn device_key(username: &str, password: &str, salt: &str) -> Vec<u8> {
    let material = format!("{}:Login to {}:{}", username, salt, password);
    let digest = Md5::digest(material.as_bytes());
    // Upper-case hex of the digest, used as key material in that textual form
    // — not the raw 16 bytes.
    format!("{:X}", digest).into_bytes()
}

/// Encrypt the local address the device is told to call back on.
pub fn encrypt_addr(key: &[u8], nonce: u32, data: &str) -> String {
    let mut derived = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        key,
        nonce.to_string().as_bytes(),
        PBKDF2_ROUNDS,
        &mut derived,
    );

    let mut buffer = data.as_bytes().to_vec();
    AesOfb::new(&derived.into(), IV.into()).apply_keystream(&mut buffer);
    base64::engine::general_purpose::STANDARD.encode(buffer)
}

/// The signed `<body>` prefix proving the caller knows the device password.
///
/// `created` is passed in rather than read from the clock so the value that
/// goes into the signature is the same one that goes into the XML — computing
/// it twice can straddle a second boundary and produce a signature the device
/// rejects for no visible reason.
pub fn auth_block(
    username: &str,
    key: &[u8],
    nonce: u32,
    salt: &str,
    payload: &str,
    created: i64,
) -> String {
    let message = format!("{}{}{}", nonce, created, payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    // A device that reported no salt expects the element to be absent, not
    // present and empty.
    let salt_element = if salt.is_empty() {
        String::new()
    } else {
        format!("<RandSalt>{}</RandSalt>", salt)
    };

    format!(
        "<CreateDate>{}</CreateDate><DevAuth>{}</DevAuth><Nonce>{}</Nonce>{}<UserName>{}</UserName>",
        created, signature, nonce, salt_element, username
    )
}
