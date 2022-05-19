use bytes::{Bytes, BytesMut, BufMut};

use crate::utils;
use crate::smb::Error;
use crate::smb::common::{FindFlags, FindInfoLevel};
use crate::win::FileAttr;
use crate::smb::trans2::SubCmd;


/// Implementation of TRANS2_FIND_FIRST2 transaction2 sub-command from 2.2.6.2.1.
///
/// The InfoLevel is hard-coded to DIRCTORY_INFO, to simplify the
/// response-parser.
pub struct FindFirst2 {
    search: FileAttr,
    count: u16,
    flags: FindFlags,
    filename: String,
}


impl FindFirst2 {
    pub fn new(filename: String, search: FileAttr) -> Self {
        Self {
            search,
            filename,
            count: 1024,
            flags: FindFlags::CLOSE_ON_EOS,
        }
    }
}



impl SubCmd for FindFirst2 {
    const SETUP: u16 = 0x0001;

    const MAX_SETUP_COUNT: u8 = 0;
    const MAX_PARAM_COUNT: u16 = 10;
    const MAX_DATA_COUNT: u16 = 65535;

    fn parameter(&self) -> Result<Bytes, Error> {
        let filename = utils::encode_utf16le_0(self.filename.as_ref());

        let mut parameter = BytesMut::with_capacity(12 + filename.len());

        parameter.put_u16_le(self.search.bits());
        parameter.put_u16_le(self.count);
        parameter.put_u16_le(self.flags.bits());
        parameter.put_u16_le(FindInfoLevel::DIRECTORY_INFO.bits());
        parameter.put_u32_le(0);            // storage type must be 0
        parameter.put(filename.as_ref());

        Ok(parameter.freeze())
    }

    fn data(&self) -> Result<Bytes, Error> {
        // Normally here could be the ExtendedAttributeList if we
        // set infolevel to QUERY_EAS_FROM_LIST, but we don't support that
        // yet.
        Ok(Bytes::new())
    }
}
