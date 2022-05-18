use bitflags::bitflags;
use bytes::{Bytes, BytesMut, BufMut};

use crate::utils;
use crate::smb::Error;
use crate::win::FileAttr;
use crate::smb::trans2::SubCmd;


/// Implementation of TRANS2_FIND_FIRST2 from 2.2.6.2.
///
/// The InfoLevel is hard-coded to DIRCTORY_INFO, to simplify the
/// response-parser.
pub struct FindFirst2 {
    search: FileAttr,
    count: u16,
    flags: FindFirstFlags,
    filename: String,
}

bitflags! {
    pub struct FindFirstFlags: u16 {
        const CLOSE_AFTER_REQ       = 0x0001;
        const CLOSE_ON_EOS          = 0x0002;
        const RETURN_RESUME         = 0x0004;
        const CONTINUE_FROM_LAST    = 0x0008;
        const WITH_BACKUP_INTENT    = 0x0010;
    }

    pub struct FindFirstInfoLevel: u16 {
        const STANDARD              = 0x0001;
        const QUERY_EA_SIZE         = 0x0002;
        const QUERY_EA_FROM_LIST    = 0x0003;
        const DIRECTORY_INFO        = 0x0101;
        const FULL_DIRECTORY_INFO   = 0x0102;
        const NAMES_INFO            = 0x0103;
        const BOTH_DIRECTORY_INFO   = 0x0104;
    }
}

impl FindFirst2 {
    pub fn new(filename: String, search: FileAttr) -> Self {
        Self {
            search,
            filename,
            count: 1024,
            flags: FindFirstFlags::RETURN_RESUME | FindFirstFlags::CLOSE_ON_EOS,
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
        parameter.put_u16_le(FindFirstInfoLevel::DIRECTORY_INFO.bits());
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
