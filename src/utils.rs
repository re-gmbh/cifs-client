use std::iter;
use chrono::{DateTime, TimeZone, Utc, Local, Duration};
use md4::Md4;
use md5::{Digest, Md5};
use hmac::{Hmac, Mac};
use des::Des;
use des::cipher::{KeyInit, BlockEncrypt, generic_array::GenericArray};
use bytes::{Bytes, Buf};

pub fn encode_netbios_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii())
        .chain(iter::repeat(' '))
        .take(16)
        .flat_map(|c| {
            let h = char::from_u32(65 + (c as u32/16)).unwrap();
            let l = char::from_u32(65 + (c as u32 % 16)).unwrap();
            [h, l]
        })
        .collect()
}

/// From MS-DYTP 2.2.3: FILETIME is a 64bit value, representing the
/// number of 100-nanosecond intervals that have elapsed since January
/// 1, 1601 in UTC.
pub fn decode_windows_time(time: u64) -> DateTime<Local> {
    let base_time = Utc.ymd(1601, 1, 1).and_hms(0, 0, 0);
    let delta = Duration::microseconds((time/10) as i64);
    (base_time + delta).into()
}

pub fn encode_windows_time<Tz: TimeZone>(time: DateTime<Tz>) -> u64 {
    let base_time = Utc.ymd(1601, 1, 1).and_hms(0, 0, 0);
    let duration = time
        .signed_duration_since(base_time)
        .num_microseconds()
        .expect("your time is too far in the future");

    // we need 10th of a ms
    10 * (duration as u64)
}

pub fn get_windows_time() -> u64 {
    encode_windows_time(Utc::now())
}

pub fn hmac_md5_oneshot(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac::<Md5> as Mac>::new_from_slice(key)
            .expect("Invalid key length in HMAC - this should not happen");

    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn md4_oneshot(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(data);
    hasher.finalize().into()
}


pub fn decode_utf16le(raw: &[u8]) -> Result<String, std::char::DecodeUtf16Error> {
    let iter = (0..raw.len())
        .step_by(2)
        .map(|i| u16::from_le_bytes([raw[i], raw[i+1]]));

    std::char::decode_utf16(iter).collect()
}

pub fn encode_utf16le(msg: &str) -> Vec<u8> {
    msg.encode_utf16()
       .map(|c| c.to_le_bytes())
       .flatten()
       .collect()
}

pub fn encode_utf16le_0(msg: &str) -> Vec<u8> {
    let mut result = encode_utf16le(msg);
    result.push(0);
    result.push(0);
    result
}

pub enum ParseStrError {
    MissingTermination,
    InvalidUnicode,
}

pub fn parse_str_0(buffer: &mut Bytes) -> Result<String, ParseStrError> {
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

pub fn parse_utf16le_0(buffer: &mut Bytes) -> Result<String, ParseStrError> {
    let mut data: Vec<u16> = Vec::new();

    while buffer.remaining() >= 2 {
        let next = buffer.get_u16_le();
        if next == 0 {
            return std::char::decode_utf16(data.into_iter())
                .map(|c| c.map_err(|_| ParseStrError::InvalidUnicode))
                .collect();
        }

        data.push(next);
    }

    Err(ParseStrError::MissingTermination)
}

/// Windows uses backslash as a path separator, which is not only very unusual
/// in the unix world but also unconvenient because it must be escaped.
/// So we allow users of Cifs to use '/' instead and replace it here.
pub fn sanitize_path(path: &str) -> String {
    path.replace('/', "\\")
}

/// returns the smallest r := 4*k with r >= n
pub fn round_up_4n(n: usize) -> usize {
    4 * ((n+3) / 4)
}

/// returns round_up_4n(n) - n
pub fn fill_up_4n(n: usize) -> usize {
    (4 - n % 4) % 4
}

/// try subtracting b from a and return None in case of underflow
pub fn try_sub(a: usize, b: usize) -> Option<usize> {
    if a < b {
        None
    } else {
        Some(a - b)
    }
}


fn expand_des_key(data: &[u8]) -> [u8; 8] {
    let mut padded = [0u8; 8];
    padded[1..1+data.len()].clone_from_slice(data);

    let mut value = u64::from_be_bytes(padded);
    let mut result: u64 = 0;

    for i in 0..8 {
        result |= (value & 0x7f) << (i*8+1);
        value >>= 7;
    }

    result.to_be_bytes()
}

pub fn des_oneshot(secret: &[u8], input: &[u8], output: &mut [u8]) {
    let key = expand_des_key(secret);
    let cipher = Des::new_from_slice(&key).unwrap();
    let array_in = GenericArray::from_slice(input);
    let mut array_out = GenericArray::from_mut_slice(output);
    cipher.encrypt_block_b2b(&array_in, &mut array_out);
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_time() {
        let start = Utc::now();
        let wintime = encode_windows_time(start);
        let check = decode_windows_time(wintime);
        let delta = check.signed_duration_since(start)
                         .num_microseconds()
                         .unwrap();

        assert_eq!(delta, 0);
    }
}
