use std::fmt;

use crate::ntlm;


#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    InputParam(String),
    NTLMError(ntlm::Error),
    InvalidMsgType(u8),
    UnexpectedEOF,
    FrameTooBig,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(what) => write!(f, "io error: {}", what),
            Error::InputParam(what) => write!(f, "invalid input value: {}", what),
            Error::NTLMError(err) => write!(f, "NTLM error: {}", err),
            Error::InvalidMsgType(v) => write!(f, "invalid NetBIOS message type: {:02x}", v),
            Error::UnexpectedEOF => write!(f, "unexpected end of stream"),
            Error::FrameTooBig => write!(f, "frame exceeds maximal size"),
        }
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(_error: std::num::TryFromIntError) -> Self {
        Error::InputParam("numeric conversion failed".to_owned())
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<ntlm::Error> for Error {
    fn from(error: ntlm::Error) -> Self {
        Error::NTLMError(error)
    }
}
