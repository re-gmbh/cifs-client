use tokio::net::TcpStream;
use bytes::Bytes;

use crate::win::NotifyAction;
use crate::{Error, Auth, smb, ntlm};
use crate::netbios::NetBios;
use crate::smb::{SmbOpts, msg, reply, trans};
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
        let server_setup = self.smb_negotiate().await?;

        // update connection options based on what we learned
        self.opts.max_smb_size = server_setup.max_buffer_size as usize;
        self.opts.unicode = server_setup.capabilities.contains(smb::Capabilities::UNICODE);

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

    pub async fn umount(&mut self, share: Share) -> Result<(), Error> {
        let _: reply::TreeDisconnect = self.command(msg::TreeDisconnect::new(share.tid)).await?;
        Ok(())
    }

    pub async fn openfile(&mut self, share: &Share, path: &str)
        -> Result<FileHandle, Error>
    {
        let filename = path.replace("/", "\\");
        self.command(msg::Open::file_ro(share.tid, filename)).await
    }

    pub async fn opendir(&mut self, share: &Share, path: &str)
        -> Result<FileHandle, Error>
    {
        let filename = path.replace("/", "\\");
        self.command(msg::Open::dir(share.tid, filename)).await
    }

    pub async fn close(&mut self, file: FileHandle) -> Result<(), Error> {
        let _: reply::Close = self.command(msg::Close::handle(file)).await?;
        Ok(())
    }

    pub async fn read(&mut self, file: &FileHandle, offset: u64) -> Result<Bytes, Error> {
        let reply: reply::Read = self.command(msg::Read::handle(file, offset)).await?;
        Ok(reply.data)
    }

    pub async fn download(&mut self, share: &Share, path: &str) -> Result<Vec<u8>, Error> {
        let file = self.openfile(share, path).await?;

        let mut data = Vec::new();
        while (data.len() as u64) < file.size {
            let chunk = self.read(&file, data.len() as u64).await?;
            data.extend_from_slice(chunk.as_ref());
        }

        self.close(file).await?;
        Ok(data)
    }

    pub async fn notify(&mut self, handle: &FileHandle)
        -> Result<Vec<(String, NotifyAction)>, Error>
    {
        let mode = trans::NotifyMode::all();
        let recursive = false;
        let subcmd = trans::NotifySetup::new(handle.fid, mode, recursive);
        let msg = msg::Transact::new(handle.tid, subcmd);
        let reply: reply::Transact<trans::NotifyResponse> = self.command(msg).await?;

        Ok(reply.subcmd.changes)
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

    async fn smb_negotiate(&mut self) -> Result<reply::ServerSetup, Error> {
        self.command(msg::Negotiate{}).await
    }

    async fn smb_session_setup(&mut self, blob: Bytes)
        -> Result<reply::SessionSetup, Error>
    {
        self.command(msg::SessionSetup::new(blob)).await
    }
}
