use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream;
use bytes::{Bytes, BytesMut, BufMut};
use crate::Error;

const MAX_FRAME_LENGTH: usize = 0x1ffff;

pub struct NetBios {
    stream: TcpStream,
}

impl NetBios {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream
        }
    }

    pub async fn write_frame(&mut self, msg: Bytes) -> Result<(), Error> {
        if msg.len() > MAX_FRAME_LENGTH {
            return Err(Error::InputParam("message too long for frame".to_owned()));
        }

        let n: u32 = msg.len().try_into()?;

        // build frame
        let mut frame = BytesMut::with_capacity(4 + msg.len());
        frame.put_u8(0);
        frame.put(&n.to_be_bytes()[1..4]);
        frame.put(msg);

        // send it
        self.stream.write_all(&frame[..]).await?;
        self.stream.flush().await?;

        Ok(())
    }

    pub async fn read_frame(&mut self) -> Result<Bytes, Error> {
        let length = self.read_frame_header().await?;

        // now read the frame payload
        let mut buffer = BytesMut::with_capacity(length);
        self.read_exactly(&mut buffer, length).await?;

        Ok(buffer.freeze())
    }

    async fn read_frame_header(&mut self) -> Result<usize, Error> {
        loop {
            // read NetBIOS message type
            let msg_type = self.stream.read_u8().await?;
            if msg_type != 0 && msg_type != 0x85 {
                return Err(Error::InvalidFrameType(msg_type));
            }

            // NetBIOS length is given by 3 bytes in big-endian...
            // (well, not really.. but good enough)
            let mut raw_length = [0u8; 4];
            self.stream.read_exact(&mut raw_length[1..4]).await?;
            let length = u32::from_be_bytes(raw_length) as usize;

            if length > MAX_FRAME_LENGTH {
                return Err(Error::FrameTooBig);
            }

            if msg_type == 0x00 {
                return Ok(length)
            }

            // keepalive with positive frame length is not allowed
            if length > 0 {
                return Err(Error::InvalidFrame);
            }
        }
    }

    async fn read_exactly(&mut self, buffer: &mut BytesMut, mut count: usize)
        -> Result<(), Error>
    {
        if count > buffer.remaining_mut() {
            return Err(Error::FrameTooBig);
        }

        let mut chunk = (&mut self.stream).take(count as u64);

        while count > 0 {
            let n = chunk.read_buf(buffer).await?;
            if n == 0 {
                return Err(Error::UnexpectedEOF);
            }

            count -= n;
        }

        Ok(())
    }
}
