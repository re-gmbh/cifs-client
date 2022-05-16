use std::fmt;

use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use bytes::{Bytes, Buf, BytesMut, BufMut};

use crate::win::NTStatus;
use super::Error;
use super::common::{SMB_HEADER_LEN, SMB_MAGIC};

/// Info is the information from SMB header
#[derive(Debug)]
pub struct Info {
    pub cmd: Cmd,
    pub status: Status,
    pub flags1: Flags1,
    pub flags2: Flags2,
    pub pid: u32,
    pub tid: u16,
    pub uid: u16,
    pub mid: u16,
}

impl Info {
    pub fn default(cmd: Cmd) -> Self {
        Info {
            cmd,
            flags1: Flags1::default(),
            flags2: Flags2::default(),
            status: Status::Known(NTStatus::SUCCESS),
            pid: 0xfeff,        // 0xffff in pid_low is not allowed by spec
            tid: 0xffff,
            uid: 0,
            mid: 0,
        }
    }

    pub fn parse(buffer: &mut Bytes) -> Result<Self, Error> {
        // check if we have at least our SMB header?
        if buffer.remaining() < SMB_HEADER_LEN {
            return Err(Error::InvalidHeader);
        }

        // check magic
        let magic = buffer.copy_to_bytes(4);
        if &magic[..] != SMB_MAGIC {
            return Err(Error::InvalidHeader);
        }

        let cmd: Cmd = buffer.get_u8().try_into()?;
        let status = buffer.get_u32_le().into();
        let flags1 = Flags1::from_bits_truncate(buffer.get_u8());
        let flags2 = Flags2::from_bits_truncate(buffer.get_u16_le());
        let pid_high = buffer.get_u16_le();

        buffer.advance(8);  // ignore 64bit "signature"
        buffer.advance(2);  // ignore 2 bytes reserved data

        let tid = buffer.get_u16_le();
        let pid_low = buffer.get_u16_le();
        let uid = buffer.get_u16_le();
        let mid = buffer.get_u16_le();
        let pid = ((pid_high as u32) << 16) | (pid_low as u32);

        // this must be a reply
        if !flags1.contains(Flags1::REPLY) {
            return Err(Error::ReplyExpected);
        }


        let info = Info {
            cmd,
            status,
            flags1,
            flags2,
            pid,
            tid,
            uid,
            mid,
        };

        Ok(info)
    }

    pub fn write(&self, buffer: &mut BytesMut) {
        let pid_high = (self.pid >> 16) as u16;
        let pid_low = (self.pid & 0xffff) as u16;

        // write header
        buffer.put(&SMB_MAGIC[..]);
        buffer.put_u8(self.cmd as u8);
        buffer.put_u32_le(self.status.into());
        buffer.put_u8(self.flags1.bits());
        buffer.put_u16_le(self.flags2.bits());
        buffer.put_u16_le(pid_high);
        buffer.put_bytes(0, 8);         // write zero "signature"
        buffer.put_bytes(0, 2);         // 2 bytes reserved
        buffer.put_u16_le(self.tid);
        buffer.put_u16_le(pid_low);
        buffer.put_u16_le(self.uid);
        buffer.put_u16_le(self.mid);
    }
}


bitflags! {
    pub struct Flags1: u8 {
        const LOCK_AND_READ_OK      = 0x01;
        const BUFFER_AVAILABLE      = 0x02;
        const RESERVED1             = 0x04;
        const CASE_INSENSITIVE      = 0x08;
        const CANONICAL_PATHS       = 0x10;
        const OPLOCK                = 0x20;
        const OPBATCH               = 0x40;
        const REPLY                 = 0x80;
    }

    pub struct Flags2: u16 {
        const LONG_NAMES_ALLOWED    = 0x0001;
        const EAS                   = 0x0002;
        const SIGNATURE_SUPPORTED   = 0x0004;
        const SIGNATURE_REQUIRED    = 0x0010;
        const LONG_NAMES_USED       = 0x0040;
        const EXTENDED_SECURITY     = 0x0800;
        const DFS                   = 0x1000;
        const PAGING_IO             = 0x2000;
        const NTSTATUS              = 0x4000;
        const UNICODE               = 0x8000;
    }
}

impl Flags1 {
    pub fn default() -> Self {
        Flags1::CASE_INSENSITIVE | Flags1::CANONICAL_PATHS
    }
}

impl Flags2 {
    pub fn default() -> Self {
        Flags2::UNICODE
      | Flags2::NTSTATUS
      | Flags2::EXTENDED_SECURITY
      | Flags2::LONG_NAMES_USED
      | Flags2::EAS
      | Flags2::LONG_NAMES_ALLOWED
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Known(NTStatus),
    Unknown(u32),
}

impl From<u32> for Status {
    fn from(code: u32) -> Self {
        match code.try_into() {
            Ok(status) => Status::Known(status),
            Err(_) => Status::Unknown(code),
        }
    }
}

impl From<Status> for u32 {
    fn from(status: Status) -> Self {
        match status {
            Status::Known(nt) => nt as u32,
            Status::Unknown(x) => x,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Status::Known(x) => write!(f, "{:?}", x),
            Status::Unknown(x) => write!(f, "Unknown ({:02x})", x),
        }
    }
}

impl Status {
    pub fn is_success(&self) -> bool {
        *self == Status::Known(NTStatus::SUCCESS)
    }

    pub fn is_failure(&self) -> bool {
        !self.is_success()
    }
}


/// Cmd defines the command codes for SMB header and AndX structure
#[derive(Debug, Clone, Copy, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Cmd {
    Rmdir = 0x01,
    Close = 0x04,
    Delete = 0x06,
    Read = 0x2e,
    Transact2 = 0x32,
    TreeDisconnect = 0x71,
    Negotiate = 0x72,
    SessionSetup = 0x73,
    TreeConnect = 0x75,
    Transact = 0xa0,
    Create = 0xa2,
    NoCommand = 0xff,
}


#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use hex_literal::hex;
    use super::*;
    use crate::smb::common::SMB_MAX_LEN;

    #[test]
    fn write_header() {
        let mut buffer = BytesMut::with_capacity(SMB_MAX_LEN);

        let info = Info::default(Cmd::Negotiate);
        info.write(&mut buffer);

        assert_eq!(buffer.as_ref(), hex!("ff534d4272000000001843c8000000000000000000000000fffffffe00000000"));
    }

    #[test]
    fn parse_header() {
        let mut buffer = Bytes::from(hex!(
                "ff534d4272000000009853c8000000000000000000000000fffffffe00000000"
            ).as_ref());

        let info = Info::parse(&mut buffer).expect("can't parse SMB header");

        assert_eq!(info.status, Status::Known(NTStatus::SUCCESS));
        assert_eq!(info.flags1, Flags1::REPLY
                              | Flags1::CASE_INSENSITIVE
                              | Flags1::CANONICAL_PATHS);

        assert_eq!(info.flags2, Flags2::UNICODE
                              | Flags2::NTSTATUS
                              | Flags2::EXTENDED_SECURITY
                              | Flags2::LONG_NAMES_USED
                              | Flags2::SIGNATURE_REQUIRED
                              | Flags2::EAS
                              | Flags2::LONG_NAMES_ALLOWED);

        assert_eq!(info.pid, 65279);
        assert_eq!(info.tid, 0xffff);
        assert_eq!(info.uid, 0);
        assert_eq!(info.mid, 0);
    }
}
