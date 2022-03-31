use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use bytes::{Bytes, BytesMut, BufMut};

use crate::{Error, Auth};
use crate::smb::{Info, Capabilities, msg, reply};
use crate::ntlm;

const MAX_FRAME_LENGTH: usize = 0x1ffff;

#[derive(Debug)]
pub struct ConnectionState {
    name: String,
    max_smb_size: usize,
    server_capabilities: Capabilities,
}


pub struct Cifs {
    auth: Auth,
    stream: TcpStream,

    info: Info,

    pub state: Option<ConnectionState>,
}


impl Cifs {
    pub fn new(auth: Auth, stream: TcpStream) -> Self {
        Cifs {
            auth,
            stream,
            info: Info::default(),
            state: None,
        }
    }


    pub async fn connect(&mut self) -> Result<(), Error> {
        let negotiated_setup = self.negotiate().await?;

        let ntlm_init_blob = {
            let mut ntlm_init = ntlm::InitMsg::new(
                 ntlm::Flags::UNICODE
               | ntlm::Flags::OEM
               | ntlm::Flags::REQUEST_TARGET
               | ntlm::Flags::NTLM
               | ntlm::Flags::DOMAIN_SUPPLIED
               | ntlm::Flags::WORKSTATION_SUPPLIED);

            ntlm_init.set_origin(&self.auth.domain, &self.auth.workstation);
            ntlm_init.set_default_version();

            ntlm_init.to_bytes().expect("can't blobify NTLM init message")
        };


        let (info, setup_response) = self.session_setup(msg::SessionSetup::new(ntlm_init_blob))
            .await?;

        // take over uid the server gave us
        self.info.uid = info.uid;

        // try to parse security blob into ntlm challenge
        let ntlm_challenge = ntlm::ChallengeMsg::parse(&setup_response.security_blob)?;
        let ntlm_response = ntlm_challenge.response(&self.auth)?;
        let (info, _) = self.session_setup(msg::SessionSetup::new(ntlm_response)).await?;

        // check status, just to be sure
        info.status.try_me()?;

        self.state = Some(ConnectionState {
            name: ntlm_challenge.target,
            max_smb_size: negotiated_setup.max_buffer_size as usize,
            server_capabilities: negotiated_setup.capabilities,
        });

        Ok(())
    }

    async fn negotiate(&mut self) -> Result<reply::Negotiate, Error> {
        self.command(msg::Negotiate{})
            .await
            .map(|v| v.1)
            .map_err(|e| e.into())
    }

    async fn session_setup(&mut self, msg: msg::SessionSetup)
        -> Result<(Info, reply::SessionSetup), Error>
    {
        self.command(msg)
            .await
            .map_err(|e| e.into())
    }


    async fn command<M,R>(&mut self, msg: M) -> Result<(Info, R), Error>
    where
        M: msg::Msg,
        R: reply::Reply,
    {
        self.write_frame(msg.info_package(&self.info)?).await?;

        reply::parse(self.read_frame().await?)
            .map_err(|e| e.into())
    }

    async fn write_frame(&mut self, msg: Bytes) -> Result<(), Error> {
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
