use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use bytes::{Bytes, BytesMut, BufMut};

use crate::error::Error;

const MAX_FRAME_LENGTH: usize = 0x1ffff;


pub struct CIFS {
    stream: TcpStream,
}


impl CIFS {
    pub fn new(stream: TcpStream) -> Self {
        CIFS {
            stream,
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

    async fn read_frame(&mut self) -> Result<Bytes, Error> {
        // read NetBIOS message type
        let msg_type = self.stream.read_u8().await?;
        if msg_type != 0 {
            return Err(Error::InvalidMsgType(msg_type));
        }

        // NetBIOS length is given by 3 bytes in big-endian
        let mut raw_length = [0u8; 4];
        self.stream.read_exact(&mut raw_length[1..4]).await?;
        let n = u32::from_be_bytes(raw_length) as usize;
        if n > MAX_FRAME_LENGTH {
            return Err(Error::FrameTooBig);
        }

        // now read the frame payload
        let mut buffer = BytesMut::with_capacity(n);
        self.read_exactly(&mut buffer, n).await?;

        Ok(buffer.freeze())
    }

    async fn write_frame(&mut self, msg: &[u8]) -> Result<(), Error> {
        if msg.len() > MAX_FRAME_LENGTH {
            return Err(Error::InputParam("message too long for frame".to_owned()));
        }
        let n: u32 = msg.len().try_into()?;

        self.stream.write_u8(0).await?;
        self.stream.write_all(&n.to_be_bytes()[1..4]).await?;
        self.stream.write_all(msg).await?;

        Ok(())
    }

}