use bytes::{Bytes, Buf};

use crate::smb::{Error, DirInfo, trans2::SubReply};


/// Reply to TRANS2_FIND_FIRST2, see 2.2.6.2.2
pub struct FindFirst2 {
    pub sid: u16,
    pub count: u16,
    pub end: bool,
    pub info: Vec<DirInfo>,
}

impl SubReply for FindFirst2 {
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

        let ffreply = FindFirst2 {
            sid,
            count,
            end,
            info,
        };

        Ok(ffreply)
    }
}
