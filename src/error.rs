use std::fmt;

use crate::smb;
use crate::ntlm;


#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    SMBError(smb::Error),
    NTLMError(ntlm::Error),
    InputParam(String),
    InvalidFrameType(u8),
    UnexpectedEOF,
    FrameTooBig,
    UnexpectedReply,
    TooManyReplies(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(what) => write!(f, "io error: {}", what),
            Error::SMBError(err) => write!(f, "protocol error: {}", err),
            Error::NTLMError(err) => write!(f, "NTLM error: {}", err),
            Error::InputParam(what) => write!(f, "invalid input value: {}", what),
            Error::InvalidFrameType(v) => write!(f, "invalid NetBIOS message type: {:02x}", v),
            Error::UnexpectedEOF => write!(f, "unexpected end of stream"),
            Error::FrameTooBig => write!(f, "frame exceeds maximal size"),
            Error::UnexpectedReply => write!(f, "unexpected SMB reply"),
            Error::TooManyReplies(num) => write!(f, "we expect one reply but got {}", num),
        }
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(_error: std::num::TryFromIntError) -> Self {
        Error::InputParam("numeric conversion failed".to_owned())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
}

impl From<smb::Error> for Error {
    fn from(err: smb::Error) -> Self {
        Error::SMBError(err)
    }
}

impl From<ntlm::Error> for Error {
    fn from(err: ntlm::Error) -> Self {
        Error::NTLMError(err)
    }
}
