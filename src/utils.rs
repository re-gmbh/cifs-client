use chrono::{DateTime, TimeZone, Utc, Local, Duration};
use md4::Md4;
use md5::{Digest, Md5};
use hmac::{Hmac, Mac};
use bytes::{Bytes, Buf};

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
