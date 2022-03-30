use std::fmt;
use std::num::TryFromIntError;
use std::string::FromUtf8Error;

use bitflags::bitflags;
use bytes::{Bytes, Buf, BytesMut, BufMut};
use num_enum::{IntoPrimitive, TryFromPrimitive, TryFromPrimitiveError};


pub const SMB_MAX_LEN: usize = 4096;
pub const SMB_HEADER_LEN: usize = 32;
pub const SMB_MAGIC: &[u8] = b"\xffSMB";
pub const SMB_SUPPORTED_DIALECTS: &[&str] = &["NT LM 0.12"];



#[derive(Debug)]
pub enum Error {
    InvalidHeader,
    InvalidData,
    InvalidCommand(u8),
    NoDialect,
    ReplyExpected,
    NeedSecurityExt,
    Unsupported(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidHeader => write!(f, "invalid header"),
            Error::InvalidData => write!(f, "invalid data"),
            Error::InvalidCommand(cmd) => write!(f, "invalid command: {:02x}", cmd),
            Error::NoDialect => write!(f, "no supported dialect found"),
            Error::ReplyExpected => write!(f, "reply expected, but got command"),
            Error::NeedSecurityExt => write!(f, "need security extension"),
            Error::Unsupported(what) => write!(f, "unsupported feature: {}", what),
        }
    }
}

impl From<TryFromPrimitiveError<RawCmd>> for Error {
    fn from(err: TryFromPrimitiveError<RawCmd>) -> Self {
        Error::InvalidCommand(err.number)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_err: FromUtf8Error) -> Self {
        Error::InvalidData
    }
}

impl From<TryFromIntError> for Error {
    fn from(_err: TryFromIntError) -> Self {
        Error::InvalidData
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
      //| Flags2::LONG_NAMES_USED
      | Flags2::EAS
      | Flags2::LONG_NAMES_ALLOWED
    }
}


impl Capabilities {
    pub fn default() -> Self {
        Capabilities::UNICODE
      | Capabilities::NT_SMBS
      | Capabilities::NTSTATUS
      | Capabilities::LEVEL2_OPLOCKS
      | Capabilities::DYNAMIC_REAUTH
      | Capabilities::EXTENDED_SECURITY
    }
}




/// NTStatus is the status code reported in a SMB header.
/// This would ideally be a C-enum of the following list:
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
/// But since i'm not that crazy i plan to only defined values used in in ERRDOS table
/// and translate them according to this table
pub type NTStatus = u32;



/// RawCmd defines the command codes for SMB header and AndX structure
#[derive(Debug, Clone, Copy, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum RawCmd {
    Close = 0x04,
    Read = 0x2e,
    Transaction2 = 0x32,
    Negotiate = 0x72,
    SessionSetup = 0x73,
    TreeConnect = 0x75,
    NoCommand = 0xff,
}



impl RawCmd {
    pub fn has_andx(&self) -> bool {
        match self {
            RawCmd::Close => false,
            RawCmd::Read => true,
            RawCmd::Transaction2 => false,
            RawCmd::Negotiate => false,
            RawCmd::SessionSetup => true,
            RawCmd::TreeConnect => true,
            RawCmd::NoCommand => false,
        }
    }
}


/// Info is the information from SMB header
#[derive(Debug)]
pub struct Info {
    pub status: NTStatus,
    pub flags1: Flags1,
    pub flags2: Flags2,
    pub pid: u32,
    pub tid: u16,
    pub uid: u16,
    pub mid: u16,
}

impl Info {
    pub fn default() -> Self {
        Info {
            flags1: Flags1::default(),
            flags2: Flags2::default(),
            status: 0,
            pid: 0xfeff,        // 0xffff in pid_low is not allowed by spec
            tid: 0xffff,
            uid: 0,
            mid: 0,
        }
    }

    pub fn parse(buffer: &mut Bytes) -> Result<Self, Error> {
        if buffer.remaining() < 27 {
            return Err(Error::InvalidHeader);
        }

        let status = buffer.get_u32_le() as NTStatus;

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


        let info = Info {
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

    pub fn write(&self, buffer: &mut BytesMut) -> Result<(), Error> {
        let pid_high = (self.pid >> 16) as u16;
        let pid_low = (self.pid & 0xffff) as u16;

        buffer.put_u32_le(self.status as u32);
        buffer.put_u8(self.flags1.bits());
        buffer.put_u16_le(self.flags2.bits());
        buffer.put_u16_le(pid_high);
        buffer.put_bytes(0, 8);         // write zero "signature"
        buffer.put_bytes(0, 2);         // 2 bytes reserved
        buffer.put_u16_le(self.tid);
        buffer.put_u16_le(pid_low);
        buffer.put_u16_le(self.uid);
        buffer.put_u16_le(self.mid);

        Ok(())
    }
}


/// AndX is used by SMB to chain commands or replies
pub struct AndX {
    pub cmd: RawCmd,
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

    pub fn write(&self, buffer: &mut BytesMut) -> Result<(), Error> {
        buffer.put_u8(self.cmd as u8);
        buffer.put_u8(0);
        buffer.put_u16_le(self.offset);
        Ok(())
    }
}
