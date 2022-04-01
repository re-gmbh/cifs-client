use tokio::net::TcpStream;

use crate::{Error, Auth, smb, ntlm};
use crate::netbios::NetBios;
use crate::smb::{SmbOpts, Info, msg, reply};


pub struct Cifs {
    netbios: NetBios,
    auth: Auth,

    opts: SmbOpts,
    info: Info,
}


impl Cifs {
    pub fn new(auth: Auth, stream: TcpStream) -> Self {
        Cifs {
            netbios: NetBios::new(stream),
            auth,
            opts: SmbOpts::default(),
            info: Info::default(),
        }
    }


    pub async fn connect(&mut self) -> Result<(), Error> {
        let negotiated_setup = self.negotiate().await?;

        // update connection options based on what we learned
        self.opts = SmbOpts {
            max_smb_size: negotiated_setup.max_buffer_size as usize,
            unicode: negotiated_setup.capabilities.contains(smb::Capabilities::UNICODE),
        };

        self.info.flags2.set(smb::Flags2::UNICODE, self.opts.unicode);

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

        Ok(())
    }

    pub async fn tree_connect(&mut self, path: &str, password: &str)
        -> Result<(Info, reply::TreeConnect), Error>
    {
        self.command(msg::TreeConnect::new(path, password))
            .await
            .map_err(|e| e.into())
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
        self.netbios.write_frame(msg.info_package(&self.opts, &self.info)?).await?;

        reply::parse(self.netbios.read_frame().await?)
            .map_err(|e| e.into())
    }
}
