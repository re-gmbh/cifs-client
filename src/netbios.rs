use std::fmt;
use std::str::FromStr;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream;
use bytes::{Bytes, Buf, BytesMut, BufMut};
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


impl Frame {
    fn new(frame_type: u8, frame_data: Bytes) -> Result<Frame, Error> {
        match frame_type {
            0x00 => Ok(Frame::Message(frame_data)),

            0x81 => Ok(Frame::SessionRequest(frame_data)),

            0x82 => if frame_data.len() != 0 {
                Err(Error::InvalidFrame)
            } else {
                Ok(Frame::PositiveResponse)
            },

            0x83 => if frame_data.len() != 1 {
                Err(Error::InvalidFrame)
            } else {
                Ok(Frame::NegativeResponse(frame_data[0]))
            }

            0x84 => if frame_data.len() != 6 {
                Err(Error::InvalidFrame)
            } else {
                // TODO should parse ip address and port here
                Ok(Frame::Retarget)
            }

            0x85 => if frame_data.len() != 0 {
                Err(Error::InvalidFrame)
            } else {
                Ok(Frame::Keepalive)
            }

            _ => Err(Error::InvalidFrameType(frame_type)),
        }
    }

    fn get_type(&self) -> u8 {
        match self {
            Frame::Message(_) => 0x00,
            Frame::SessionRequest(_) => 0x81,
            Frame::PositiveResponse => 0x82,
            Frame::NegativeResponse(_) => 0x83,
            Frame::Retarget => 0x84,
            Frame::Keepalive => 0x85,
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
                encoding.put_u8(self.get_type());
                encoding.put(&n.to_be_bytes()[1..4]);
                encoding.put(&msg[..]);
                Ok(encoding.freeze())
            }


            Frame::SessionRequest(msg) => {
                if msg.len() != 68 {
                    return Err(Error::InvalidFrame);
                }

                let mut encoding = BytesMut::with_capacity(4 + msg.len());
                encoding.put_u8(self.get_type());
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
        let stream = TcpStream::connect((host, port)).await?;
        Ok(Self::from_stream(stream))
    }

    pub async fn open(host: &str, myname: &str) -> Result<Self, Error> {
        if let Ok(mut netbios) = Self::open_raw(host, 139).await {
            // Port 139 runs the NetBios Session Service: Here we have to
            // create a session first before doing anything.

            // derive remote name from hostname: if host is an ip address
            // we fallback to a constant dummy name.
            let remote = if let Ok(_) = std::net::IpAddr::from_str(host) {
                "*SMBSERVER"
            } else {
                host
            };

            netbios.create_session(remote, myname).await?;

            Ok(netbios)
        } else {
            // Try port 445 next
            Self::open_raw(host, 445).await
        }
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

        // NetBIOS length is given by 3 bytes in big-endian...
        // (well, not really.. but good enough for us)
        let mut raw_length = [0u8; 4];
        self.stream.read_exact(&mut raw_length[1..4]).await?;
        let msg_length = u32::from_be_bytes(raw_length) as usize;
        if msg_length > MAX_FRAME_LENGTH {
            return Err(Error::FrameTooBig);
        }

        // read frame payload
        let msg_data = self.read_exactly(msg_length).await?;

        Frame::new(msg_type, msg_data)
    }


    async fn read_exactly(&mut self, mut count: usize)
        -> Result<Bytes, Error>
    {
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
        while buffer.has_remaining() {
            let _ = self.stream.write_buf(&mut buffer).await?;
        }
        self.stream.flush().await?;
        Ok(())
    }
}
