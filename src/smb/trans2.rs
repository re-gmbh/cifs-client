use bitflags::bitflags;
use bytes::{Bytes, Buf, BytesMut, BufMut};

use crate::utils;
use crate::win::{FileAttr, ExtFileAttr};
use super::Error;


/// Specification of a so called "Trans2 subcommand" that can be used in
/// msg::Transact2 messages, see 2.2.6 in CIFS Spec.
pub trait SubCmd {
    const SETUP: u16;
    const MAX_SETUP_COUNT: u8;
    const MAX_PARAM_COUNT: u16;
    const MAX_DATA_COUNT: u16;

    fn parameter(&self) -> Result<Bytes, Error> {
        Ok(Bytes::new())
    }

    fn data(&self) -> Result<Bytes, Error> {
        Ok(Bytes::new())
    }
}

pub trait SubReply: Sized {
    const SETUP: u16;

    fn parse(parameter: Bytes, data: Bytes) -> Result<Self, Error>;
}



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

    const MAX_SETUP_COUNT: u8 = 0;      // TODO: needs checking
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


/// Dirctory Info for FindFirst2Reply and FirstNext2Reply, see 2.2.8.1.4
/// We use this over the other ones, because here we get a 64bit file size.
#[derive(Debug)]
pub struct DirInfo {
    pub creation_time: u64,
    pub access_time: u64,
    pub write_time: u64,
    pub change_time: u64,
    pub filename: String,
    pub filesize: u64,
    pub attributes: ExtFileAttr,
}

impl DirInfo {
    fn parse(mut data: Bytes) -> Result<Self, Error> {
        if data.remaining() < 60 {
            return Err(Error::InvalidData);
        }

        // directory info normally starts with a "next entry offset" (u32le)
        // which i moved outside of this structure

        data.advance(4);    // ignore file index as recommended by spec

        // FIXME should have a real time datatime
        let creation_time = data.get_u64_le();
        let access_time = data.get_u64_le();
        let write_time = data.get_u64_le();
        let change_time = data.get_u64_le();

        let filesize = data.get_u64_le();
        data.advance(8);    // ignore allocation size, as we don't need it
        let attributes = ExtFileAttr::from_bits_truncate(data.get_u32_le());
        let filename_length = data.get_u32_le() as usize;

        if data.remaining() < filename_length {
            return Err(Error::InvalidData);
        }

        let raw_filename = data.copy_to_bytes(filename_length);

        // FIXME: caller should inform us, if this is unicode or not
        let filename = utils::decode_utf16le(raw_filename.as_ref())?;

        let info = DirInfo {
            creation_time,
            access_time,
            write_time,
            change_time,
            filename,
            filesize,
            attributes,
        };

        Ok(info)
    }
}


/// Reply to TRANS2_FIND_FIRST2, see 2.2.6.2.2
pub struct FindFirst2Reply {
    pub sid: u16,
    pub count: u16,
    pub end: bool,
    pub info: Vec<DirInfo>,
}

impl SubReply for FindFirst2Reply {
    const SETUP: u16 = 0x0001;

    fn parse(mut parameter: Bytes, mut data: Bytes) -> Result<Self, Error> {
        // parameter
        if parameter.remaining() < 10 {
            return Err(Error::InvalidData);
        }

        let sid = parameter.get_u16_le();
        let count = parameter.get_u16_le();
        let end = parameter.get_u16_le() != 0;
        parameter.advance(2);

        // offset of last dir info (relativ to SMB header)
        //let offset = parameter.get_u16_le();


        // data
        let mut info = Vec::new();
        loop {
            if data.remaining() == 0 {
                break;
            }
            if data.remaining() < 4 {
                return Err(Error::InvalidData);
            }

            let rawsize = data.get_u32_le();
            if rawsize < 4 {
                return Err(Error::InvalidData);
            }

            let size = (rawsize - 4) as usize;
            if size == 0 {
                break;
            }

            if data.remaining() < size {
                return Err(Error::InvalidData);
            }

            let rawinfo = data.copy_to_bytes(size);
            info.push(DirInfo::parse(rawinfo)?);
        }

        let ffreply = FindFirst2Reply {
            sid,
            count,
            end,
            info,
        };

        Ok(ffreply)
    }
}
