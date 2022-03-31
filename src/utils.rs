use chrono::{Utc, TimeZone};
use md4::Md4;
use md5::{Digest, Md5};
use hmac::{Hmac, Mac};
use bytes::{Bytes, Buf};


pub fn to_utf16le(data: &str) -> Vec<u8> {
    data.encode_utf16()
        .map(|c| c.to_le_bytes())
        .fold(Vec::new(), |mut acc, x| { acc.extend_from_slice(&x); acc } )
}

pub fn get_windows_time() -> u64 {
    let back_then = Utc.ymd(1601, 1, 1).and_hms(0, 1, 1);
    let now = Utc::now();

    let duration = now.signed_duration_since(back_then)
       .num_microseconds()
       .expect("you found a 300000 years old bug (or your clock is slightly off)");

    // we need 10th of a ms
    10 * (duration as u64)
}

pub fn hmac_md5_oneshot(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(key)
            .expect("Invalid key length in HMAC - this should not happen");

    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn md4_oneshot(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(data);
    hasher.finalize().into()
}



pub enum ParseStrError {
    MissingTermination,
    InvalidUnicode,
}

#[allow(dead_code)]
pub fn parse_str0(buffer: &mut Bytes) -> Result<String, ParseStrError> {
    let mut data = Vec::new();

    while buffer.has_remaining() {
        let c = buffer.get_u8();
        if c == 0 {
            return String::from_utf8(data)
                .map_err(|_| ParseStrError::InvalidUnicode);
        }

        data.push(c);
    }

    Err(ParseStrError::MissingTermination)
}

pub fn encode_utf16le(msg: &str) -> Vec<u8> {
    msg.encode_utf16()
       .map(|c| c.to_le_bytes())
       .flatten()
       .collect()
}

pub fn parse_utf16le(raw: &[u8]) -> Result<String, std::char::DecodeUtf16Error> {
    let iter = (0..raw.len())
        .step_by(2)
        .map(|i| u16::from_le_bytes([raw[i], raw[i+1]]));

    std::char::decode_utf16(iter).collect()
}
