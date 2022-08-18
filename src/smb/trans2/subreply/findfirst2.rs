use bytes::{Bytes, Buf};

use crate::smb::{Error, DirInfo, trans2::SubReply};


/// Reply to TRANS2_FIND_FIRST2, see 2.2.6.2.2
pub struct FindFirst2 {
    pub sid: u16,
    pub end: bool,
    pub info: Vec<DirInfo>,
}

impl SubReply for FindFirst2 {
    const SETUP: u16 = 0x0001;

    fn parse(mut parameter: Bytes, mut data: Bytes) -> Result<Self, Error> {
        // parse subreply parameter
        if parameter.remaining() < 10 {
            return Err(Error::InvalidData);
        }

        let sid = parameter.get_u16_le();
        let count = parameter.get_u16_le() as usize;
        let end = parameter.get_u16_le() != 0;
        parameter.advance(2);

        // Offset of last dir info (relativ to SMB header). Right now we can't
        // use the offset here, since we don't now where in the SMB frame we are.
        // I hope, that the last dir info is allways simply the last in the following
        // list so we don't need the offset...
        //let last_entry_offset = parameter.get_u16_le();


        // parse subreply data
        let mut info = Vec::with_capacity(count);
        loop {
            if data.remaining() == 0 {
                break;
            }
            if data.remaining() < 4 {
                return Err(Error::InvalidData);
            }

            let next_entry = data.get_u32_le();
            let size = if next_entry == 0 {
                data.remaining()
            } else if next_entry >= 4 {
                (next_entry - 4) as usize
            } else {
                return Err(Error::InvalidData);
            };

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

        let subreply = FindFirst2 {
            sid,
            end,
            info,
        };

        Ok(subreply)
    }
}
