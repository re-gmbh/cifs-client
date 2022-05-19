use bytes::{Bytes, Buf};

use crate::smb::{Error, DirInfo, trans2::SubReply};

/// Reply to TRANS2_FIND_NEXT2, see 2.2.6.3.2
pub struct FindNext2 {
    pub end: bool,
    pub info: Vec<DirInfo>,
}

impl SubReply for FindNext2 {
    const SETUP: u16 = 0x0002;

    fn parse(mut parameter: Bytes, mut data: Bytes) -> Result<Self, Error> {
        // parse subreply parameter
        if parameter.remaining() < 4 {
            return Err(Error::InvalidData);
        }

        let count = parameter.get_u16_le() as usize;
        let end = parameter.get_u16_le() != 0;

        // ignore EA error offset (u16le) and last dir-entry offset (u16le).

        // parse subreply data
        let mut info = Vec::with_capacity(count);
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

        if info.len() != count {
            return Err(Error::InvalidData);
        }

        if !end && count == 0 {
            return Err(Error::InvalidData);
        }

        Ok( Self { end, info } )
    }
}
