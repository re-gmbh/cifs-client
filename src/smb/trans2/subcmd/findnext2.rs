use bytes::{Bytes, BytesMut, BufMut};

use crate::utils;
use crate::smb::{
    Error,
    common::{FindFlags, FindInfoLevel},
    trans2::SubCmd,
};

/// TRANS2_FIND_NEXT2 sub command, see 2.2.6.3.1
pub struct FindNext2 {
    sid: u16,
    count: u16,
    flags: FindFlags,
    filename: String,
}


impl FindNext2 {
    pub fn new(sid: u16, filename: String) -> Self {
        Self {
            sid,
            count: 1024,
            flags: FindFlags::CLOSE_ON_EOS,
            filename,
        }
    }
}

impl SubCmd for FindNext2 {
    const SETUP: u16 = 0x0002;

    const MAX_SETUP_COUNT: u8 = 0;
    const MAX_PARAM_COUNT: u16 = 10;
    const MAX_DATA_COUNT: u16 = 65535;

    fn parameter(&self) -> Result<Bytes, Error> {
        let filename = utils::encode_utf16le_0(self.filename.as_ref());

        let mut parameter = BytesMut::with_capacity(12 + filename.len());

        parameter.put_u16_le(self.sid);
        parameter.put_u16_le(self.count);
        parameter.put_u16_le(FindInfoLevel::DIRECTORY_INFO.bits());
        parameter.put_u32_le(0);    // resume key seems to be always 0?
        parameter.put_u16_le(self.flags.bits());
        parameter.put(filename.as_ref());

        Ok(parameter.freeze())
    }

    fn data(&self) -> Result<Bytes, Error> {
        Ok(Bytes::new())
    }
}
