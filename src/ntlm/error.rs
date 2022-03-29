use std::{io, fmt};

#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    InputParameter(String),
    InvalidPacket,
    NeedChallenge,
    NeedAuth,
    NeedWorkstation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IO(ioerr) => write!(f, "io error: {}", ioerr),
            Error::InputParameter(what) => write!(f, "invalid input paramater: {}", what),
            Error::InvalidPacket => write!(f, "invalid packet data"),
            Error::NeedChallenge => write!(f, "need to parse challenge before creating authentication"),
            Error::NeedAuth => write!(f, "authentication not configured"),
            Error::NeedWorkstation => write!(f, "workstation is needed for authentication"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(err: std::num::TryFromIntError) -> Self {
        Error::InputParameter(format!("numeric conversion: {}", err))
    }
}
