use bitflags::bitflags;
use bytes::{Bytes, Buf, BytesMut, BufMut};

use crate::utils;
use crate::win::ExtFileAttr;

use super::Error;
use super::info::Cmd;

pub(crate) const SMB_MAX_LEN: usize = 4096;
pub(crate) const SMB_HEADER_LEN: usize = 32;
pub(crate) const SMB_MAGIC: &[u8] = b"\xffSMB";
pub(crate) const SMB_SUPPORTED_DIALECTS: &[&str] = &["NT LM 0.12"];
pub(crate) const SMB_READ_MIN: u16 = 32768;
pub(crate) const SMB_READ_MAX: u16 = 65534;


bitflags! {
    pub struct Capabilities: u32 {
        const RAW_MODE              = 0x00000001;
        const MPX_MODE              = 0x00000002;
        const UNICODE               = 0x00000004;
        const LARGE_FILES           = 0x00000008;
        const NT_SMBS               = 0x00000010;
        const REMOTE_APIS           = 0x00000020;
        const NTSTATUS              = 0x00000040;
        const LEVEL2_OPLOCKS        = 0x00000080;
        const LOCK_AND_READ         = 0x00000100;
        const NT_FIND               = 0x00000200;
        const DFS                   = 0x00001000;
        const INFOLEVEL_PASS        = 0x00002000;
        const LARGE_READX           = 0x00004000;
        const LARGE_WRITEX          = 0x00008000;
        const LWIO                  = 0x00010000;
        const UNIX                  = 0x00800000;
        const COMPRESSED            = 0x02000000;
        const DYNAMIC_REAUTH        = 0x20000000;
        const PERSISTENT_HANDLES    = 0x40000000;
        const EXTENDED_SECURITY     = 0x80000000;
    }

}

/// AndX is used by SMB to chain commands or replies
pub struct AndX {
    pub cmd: Cmd,
    pub offset: u16,
}

impl AndX {
    pub fn parse(buffer: &mut Bytes) -> Result<Option<Self>, Error> {
        let cmd = buffer.get_u8();
        buffer.advance(1);                  // ignore 1 byte reserved data
        let offset = buffer.get_u16_le();

        if cmd == 0xff {
            Ok(None)
        } else {
            let andx = AndX {
                cmd: cmd.try_into()?,
                offset,
            };

            Ok(Some(andx))
        }
    }

    pub fn write(&self, buffer: &mut BytesMut) {
        buffer.put_u8(self.cmd as u8);
        buffer.put_u8(0);
        buffer.put_u16_le(self.offset);
    }
}

/// Directory Info for smb::trans2::reply::FindFirst2 and
/// smb::trans2::reply::FirstNext2, see 2.2.8.1.4.
///
/// Note: We use this one over the alternatives, because here we get a 64bit
/// file size.
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
    pub fn parse(mut data: Bytes) -> Result<Self, Error> {
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
