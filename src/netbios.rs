use std::fmt;

use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream;
use bytes::{Bytes, Buf, BytesMut, BufMut};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::utils::encode_netbios_name;

const MAX_FRAME_LENGTH: usize = 0x1ffff;

#[derive(Debug)]
pub struct NetBios {
    stream: TcpStream,
}

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    CreateSession(u8),
    InvalidFrameType(u8),
    InvalidFrame,
    FrameTooBig,
    UnexpectedFrame,
    UnexpectedEOF,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IoError(what) => write!(f, "io error: {}", what),
            Error::CreateSession(code) => write!(f, "can't create NBT session: error code 0x{:02x}", code),
            Error::InvalidFrameType(v) => write!(f, "invalid NetBIOS message type: 0x{:02x}", v),
            Error::InvalidFrame => write!(f, "invalid NetBIOS frame"),
            Error::FrameTooBig => write!(f, "frame exceeds maximal size"),
            Error::UnexpectedFrame => write!(f, "unexpected NetBIOS frame"),
            Error::UnexpectedEOF => write!(f, "unexpected end of stream"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(_: std::num::TryFromIntError) -> Self {
        Error::FrameTooBig
    }
}


enum Frame {
    Message(Bytes),
    SessionRequest(Bytes),
    PositiveResponse,
    NegativeResponse(u8),
    Retarget,
    Keepalive,
}

#[derive(IntoPrimitive, TryFromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u8)]
enum FrameType {
    MESSAGE = 0x00,
    SESSION_REQUEST = 0x81,
    POSITIVE_RESPONSE = 0x82,
    NEGATIVE_RESPONSE = 0x83,
    RETARGET = 0x84,
    KEEPALIVE = 0x85,
}


impl Frame {
    fn new(raw_frame_type: u8, frame_data: Bytes) -> Result<Frame, Error> {
        let frame_type = FrameType::try_from(raw_frame_type)
            .map_err(|_| Error::InvalidFrameType(raw_frame_type))?;

        match frame_type {
            FrameType::MESSAGE => Ok(Frame::Message(frame_data)),

            FrameType::SESSION_REQUEST => Ok(Frame::SessionRequest(frame_data)),

            FrameType::POSITIVE_RESPONSE => if frame_data.len() != 0 {
                Err(Error::InvalidFrame)
            } else {
                Ok(Frame::PositiveResponse)
            },

            FrameType::NEGATIVE_RESPONSE => if frame_data.len() != 1 {
                Err(Error::InvalidFrame)
            } else {
                Ok(Frame::NegativeResponse(frame_data[0]))
            }

            FrameType::RETARGET => if frame_data.len() != 6 {
                Err(Error::InvalidFrame)
            } else {
                // TODO should parse ip address and port here
                Ok(Frame::Retarget)
            }

            FrameType::KEEPALIVE => if frame_data.len() != 0 {
                Err(Error::InvalidFrame)
            } else {
                Ok(Frame::Keepalive)
            }
        }
    }

    fn get_type(&self) -> FrameType {
        match self {
            Frame::Message(_) => FrameType::MESSAGE,
            Frame::SessionRequest(_) => FrameType::SESSION_REQUEST,
            Frame::PositiveResponse => FrameType::POSITIVE_RESPONSE,
            Frame::NegativeResponse(_) => FrameType::NEGATIVE_RESPONSE,
            Frame::Retarget => FrameType::RETARGET,
            Frame::Keepalive => FrameType::KEEPALIVE,
        }
    }

    fn encode(&self) -> Result<Bytes, Error> {
        match self {
            Frame::Message(msg) => {
                if msg.len() > MAX_FRAME_LENGTH {
                    return Err(Error::InvalidFrame);
                }

                let n: u32 = msg.len().try_into()?;

                let mut encoding = BytesMut::with_capacity(4 + msg.len());
                encoding.put_u8(self.get_type().into());
                encoding.put(&n.to_be_bytes()[1..4]);
                encoding.put(&msg[..]);
                Ok(encoding.freeze())
            }


            Frame::SessionRequest(msg) => {
                if msg.len() != 68 {
                    return Err(Error::InvalidFrame);
                }

                let mut encoding = BytesMut::with_capacity(4 + msg.len());
                encoding.put_u8(self.get_type().into());
                encoding.put(&(u32::try_from(msg.len())?).to_be_bytes()[1..4]);
                encoding.put(&msg[..]);
                Ok(encoding.freeze())
            }

            _ => Err(Error::InvalidFrame)
        }
    }

}

impl NetBios {
    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream
        }
    }

    pub async fn open_raw(host: &str, port: u16) -> Result<Self, Error> {
        tracing::debug!("create NetBios connection to {}:{}", host, port);
        let stream = TcpStream::connect((host, port)).await?;
        Ok(Self::from_stream(stream))
    }

    pub async fn open(host: &str, myname: &str) -> Result<Self, Error> {
        let netbios = match Self::open_raw(host, 445).await {
            Ok(nb) => nb,
            Err(_) => {
                // Port 139 runs the NetBios Session Service: Here we have to
                // create a session first before doing anything.
                let mut nb = Self::open_raw(host, 139).await?;
                nb.create_session("*SMBSERVER", myname).await?;
                nb
            }
        };

        Ok(netbios)
    }


    pub async fn send_message(&mut self, msg: Bytes) -> Result<(), Error> {
        self.send(Frame::Message(msg)).await
    }

    pub async fn recv_message(&mut self) -> Result<Bytes, Error> {
        loop {
            match self.recv().await? {
                Frame::Message(msg) => return Ok(msg),
                Frame::Keepalive => (),

                _ => return Err(Error::UnexpectedFrame),
            }
        }
    }

    async fn create_session(&mut self, dst: &str, src: &str)
        -> Result<(), Error>
    {
        let mut msgbuf = BytesMut::with_capacity(68);

        msgbuf.put_u8(0x20);
        msgbuf.put(encode_netbios_name(dst).as_bytes());
        msgbuf.put_u8(0x00);

        msgbuf.put_u8(0x20);
        msgbuf.put(encode_netbios_name(src).as_bytes());
        msgbuf.put_u8(0x00);

        self.send(Frame::SessionRequest(msgbuf.freeze())).await?;

        match self.recv().await? {
            Frame::PositiveResponse => Ok(()),
            Frame::NegativeResponse(code) => Err(Error::CreateSession(code)),
            _ => Err(Error::InvalidFrame),
        }
    }




    async fn send(&mut self, frame: Frame) -> Result<(), Error> {
        self.write_exactly(frame.encode()?).await
    }

    async fn recv(&mut self) -> Result<Frame, Error> {
        // read NetBIOS message type
        let msg_type = self.stream.read_u8().await?;

        tracing::debug!("expecting NetBios msg type: {}", msg_type);

        // NetBIOS length is given by 3 bytes in big-endian...
        // (well, not really.. but good enough for us)
        let mut raw_length = [0u8; 4];
        self.stream.read_exact(&mut raw_length[1..4]).await?;
        let msg_length = u32::from_be_bytes(raw_length) as usize;
        if msg_length > MAX_FRAME_LENGTH {
            return Err(Error::FrameTooBig);
        }

        tracing::debug!("expecting NetBios msg of length {}", msg_length);

        // read frame payload
        let msg_data = self.read_exactly(msg_length).await?;

        Frame::new(msg_type, msg_data)
    }


    async fn read_exactly(&mut self, mut count: usize)
        -> Result<Bytes, Error>
    {
        tracing::debug!("reading {} bytes...", count);
        let mut buffer = BytesMut::with_capacity(count);
        let mut chunk = (&mut self.stream).take(count as u64);

        while count > 0 {
            let n = chunk.read_buf(&mut buffer).await?;
            if n == 0 {
                return Err(Error::UnexpectedEOF);
            }

            count -= n;
        }

        Ok(buffer.freeze())
    }

    async fn write_exactly(&mut self, mut buffer: Bytes) -> Result<(), Error> {
        tracing::debug!("writting {} bytes...", buffer.remaining());
        while buffer.has_remaining() {
            let _ = self.stream.write_buf(&mut buffer).await?;
        }
        self.stream.flush().await?;
        Ok(())
    }
}
