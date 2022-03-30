use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use bytes::{Bytes, BytesMut, BufMut};

use crate::{Error, Auth};
use crate::smb::{Info, msg, reply};

const MAX_FRAME_LENGTH: usize = 0x1ffff;


pub struct Cifs {
    pub auth: Auth,
    stream: TcpStream,
}


impl Cifs {
    pub fn new(auth: Auth, stream: TcpStream) -> Self {
        Cifs {
            auth,
            stream,
        }
    }


    pub async fn connect(&mut self) -> Result<(), Error> {
        let _setup = self.negotiate().await?;

        Ok(())
    }


    pub async fn negotiate(&mut self) -> Result<reply::Negotiate, Error> {
        let msg = msg::Negotiate {};
        let (_, response) = self.cmd(msg).await?;

        Ok(response)
    }

    pub async fn session_setup(&mut self, msg: msg::SessionSetup)
        -> Result<(Info, reply::SessionSetup), Error>
    {
        self.cmd(msg)
            .await
            .map_err(|e| e.into())
    }


    /*
    async fn cmd<T: smb::Reply>(&mut self, msg: impl smb::Msg)
        -> Result<(smb::Info, T), Error>
    */
    async fn cmd<M,R>(&mut self, msg: M) -> Result<(Info, R), Error>
    where
        M: msg::Msg,
        R: reply::Reply,
    {
        self.write_frame(msg.package()?)
            .await?;

        let (info, reply) = reply::parse(self.read_frame().await?)?;

        Ok((info, reply))
    }

    async fn write_frame(&mut self, msg: Bytes) -> Result<(), Error> {
        if msg.len() > MAX_FRAME_LENGTH {
            return Err(Error::InputParam("message too long for frame".to_owned()));
        }
        let n: u32 = msg.len().try_into()?;

        self.stream.write_u8(0).await?;
        self.stream.write_all(&n.to_be_bytes()[1..4]).await?;
        self.stream.write_all(&msg[..]).await?;

        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Bytes, Error> {
        // read NetBIOS message type
        let msg_type = self.stream.read_u8().await?;
        if msg_type != 0 {
            return Err(Error::InvalidFrameType(msg_type));
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
