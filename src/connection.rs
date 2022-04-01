use tokio::net::TcpStream;
use bytes::Bytes;

use crate::{Error, Auth, smb, ntlm};
use crate::netbios::NetBios;
use crate::smb::{SmbOpts, msg, reply};
use crate::smb::reply::{Share, FileHandle};


pub struct Cifs {
    netbios: NetBios,
    auth: Auth,
    opts: SmbOpts,
}


impl Cifs {
    pub fn new(auth: Auth, stream: TcpStream) -> Self {
        Cifs {
            netbios: NetBios::new(stream),
            auth,
            opts: SmbOpts::default(),
        }
    }


    pub async fn connect(&mut self) -> Result<(), Error> {
        let negotiated_setup = self.smb_negotiate().await?;

        // update connection options based on what we learned
        self.opts.max_smb_size = negotiated_setup.max_buffer_size as usize;
        self.opts.unicode = negotiated_setup.capabilities.contains(smb::Capabilities::UNICODE);

        let ntlm_init = {
            let mut ntlm_init_msg = ntlm::InitMsg::new(
                 ntlm::Flags::UNICODE
               | ntlm::Flags::OEM
               | ntlm::Flags::REQUEST_TARGET
               | ntlm::Flags::NTLM
               | ntlm::Flags::DOMAIN_SUPPLIED
               | ntlm::Flags::WORKSTATION_SUPPLIED);

            ntlm_init_msg.set_origin(&self.auth.domain, &self.auth.workstation);
            ntlm_init_msg.set_default_version();
            ntlm_init_msg.to_bytes()?
        };

        let setup_reply = self.smb_session_setup(ntlm_init).await?;

        // take over uid the server gave us
        self.opts.uid = setup_reply.uid;

        // try to parse security blob into ntlm challenge and calculate response
        let ntlm_challenge = ntlm::ChallengeMsg::parse(&setup_reply.security_blob)?;
        let ntlm_response = ntlm_challenge.response(&self.auth)?;
        let _ = self.smb_session_setup(ntlm_response).await?;

        Ok(())
    }

    pub async fn mount(&mut self, path: &str) -> Result<Share, Error> {
        self.mount_password(path, "").await
    }

    pub async fn mount_password(&mut self, path: &str, password: &str)
        -> Result<Share, Error>
    {
        let normalized = path.replace("/", "\\");
        self.command(msg::TreeConnect::new(&normalized, password)).await
    }

    pub async fn open_file(&mut self, share: &Share, name: &str)
        -> Result<FileHandle, Error>
    {
        let filename = name.replace("/", "\\");
        self.command(msg::OpenFile::ro(share.tid, filename)).await
    }

    pub async fn close(&mut self, file: FileHandle) -> Result<(), Error> {
        let _: reply::Close = self.command(msg::Close::handle(file)).await?;
        Ok(())
    }


    //
    // private SMB functions
    //
    async fn command<M,R>(&mut self, msg: M) -> Result<R, Error>
    where
        M: msg::Msg,
        R: reply::Reply,
    {
        self.netbios.write_frame(msg.to_bytes(&self.opts)?).await?;
        reply::parse(self.netbios.read_frame().await?).map_err(|e| e.into())
    }

    async fn smb_negotiate(&mut self) -> Result<reply::Negotiate, Error> {
        self.command(msg::Negotiate{}).await
    }

    async fn smb_session_setup(&mut self, blob: Bytes)
        -> Result<reply::SessionSetup, Error>
    {
        self.command(msg::SessionSetup::new(blob)).await
    }
}
