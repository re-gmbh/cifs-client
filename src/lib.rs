pub mod win;
mod error;
mod ntlm;
mod smb;
mod netbios;
mod utils;

use tokio::net::TcpStream;
use bytes::{Bytes, BytesMut};
use lazy_static::lazy_static;
use regex::Regex;

use crate::win::{NotifyAction, NTStatus};
use crate::netbios::NetBios;
use crate::smb::info::{Info, Cmd, Status, Flags2};
use crate::smb::{msg, reply, subcmd, Capabilities};

pub use error::Error;
pub use ntlm::Auth;
pub use crate::smb::reply::{Share, Handle};


#[derive(Debug)]
pub struct Cifs {
    netbios: NetBios,
    auth: Auth,

    max_smb_size: usize,
    use_unicode: bool,
    uid: u16,
    mid: u16,
}


impl Cifs {
    pub fn new(auth: Auth, stream: TcpStream) -> Self {
        Cifs {
            netbios: NetBios::new(stream),
            auth,

            max_smb_size: 1024,
            use_unicode: true,
            uid: 0,
            mid: 0,
        }
    }


    pub async fn connect(&mut self) -> Result<(), Error> {
        let server_setup = self.negotiate().await?;

        // update connection options based on what we learned
        self.max_smb_size = server_setup.max_buffer_size as usize;
        self.use_unicode = server_setup.capabilities.contains(Capabilities::UNICODE);

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

        let setup_reply = self.session_setup(ntlm_init).await?;

        // take over uid the server gave us
        self.uid = setup_reply.uid;

        // try to parse security blob into ntlm challenge and calculate response
        let ntlm_challenge = ntlm::ChallengeMsg::parse(&setup_reply.security_blob)?;
        let ntlm_response = ntlm_challenge.response(&self.auth)?;
        let _ = self.session_setup(ntlm_response).await?;

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
        -> Result<Handle, Error>
    {
        let filename = path.replace("/", "\\");
        self.command(msg::Open::file_ro(share.tid, filename)).await
    }

    pub async fn opendir(&mut self, share: &Share, path: &str)
        -> Result<Handle, Error>
    {
        let filename = path.replace("/", "\\");
        self.command(msg::Open::dir(share.tid, filename)).await
    }

    pub async fn close(&mut self, file: Handle) -> Result<(), Error> {
        let _: reply::Close = self.command(msg::Close::handle(file)).await?;
        Ok(())
    }

    pub async fn read(&mut self, file: &Handle, offset: u64) -> Result<Bytes, Error> {
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

    pub async fn delete(&mut self, share: &Share, path: &str) -> Result<(), Error> {
        let filename = path.replace("/", "\\");
        let _: reply::Delete = self.command(msg::Delete::file(share.tid, filename)).await?;
        Ok(())
    }

    pub async fn rmdir(&mut self, share: &Share, path: &str) -> Result<(), Error> {
        let name = path.replace("/", "\\");
        let _: reply::Rmdir = self.command(msg::Rmdir::new(share.tid, name)).await?;
        Ok(())
    }

    pub async fn notify(&mut self, handle: &Handle)
        -> Result<Vec<(String, NotifyAction)>, Error>
    {
        // sub-command we want to run via SMB transact
        let cmd = subcmd::NotifySetup::new(handle.fid, subcmd::NotifyMode::all(), false);
        // get sub-command response via transact
        let reply: subcmd::Notification = self.transact(handle.tid, cmd).await?;

        Ok(reply.changes)
    }




    //
    // private functions
    //

    /// Sends a generic message M and expects result generic R. There is no
    /// check that M and R "fit" together (like M::CMD == R::CMD), so this
    /// is clearly not meant to be a public method.
    /// We built safe wrapper around command, with correct message and reply
    /// types.
    async fn command<M,R>(&mut self, msg: M) -> Result<R, Error>
    where
        M: msg::Msg,
        R: reply::Reply,
    {
        let mut frame_out = BytesMut::with_capacity(self.max_smb_size);

        // allocate a multiplex id
        let mid = self.mid;
        self.mid += 1;

        // create and write SMB header
        let mut info = Info::default(M::CMD);
        info.uid = self.uid;
        info.mid = mid;
        info.flags2.set(Flags2::UNICODE, self.use_unicode);
        msg.fix_header(&mut info);
        info.write(&mut frame_out);

        // add message body to frame and send it
        msg.write(&info, &mut frame_out)?;
        self.netbios.write_frame(frame_out.freeze()).await?;

        // wait for a frame with the correct mid
        let (info, body) = loop {
            let mut frame = self.netbios.read_frame().await?;
            let info = Info::parse(&mut frame)?;
            if info.mid == mid {
                break (info, frame);
            }
        };

        // check command identifier
        if info.cmd != R::CMD {
            return Err(Error::UnexpectedReply(R::CMD, info.cmd));
        }

        // check status
        if let Status::Known(status) = info.status {
            match status {
                NTStatus::SUCCESS => (),
                NTStatus::MORE_PROCESSING if info.cmd == Cmd::SessionSetup => (),

                _ => return Err(Error::ServerError(info.status)),
            }
        } else {
            return Err(Error::ServerError(info.status));
        }

        // if extended_security is not set, we have to parse
        // negotiate reply differently. until we support that
        // we throw an error...
        if !info.flags2.contains(Flags2::EXTENDED_SECURITY) {
            return Err(Error::Unsupported("reply without extended security".to_owned()));
        }

        // finally parse the response body into our desired result
        R::parse(&info, body).map_err(|e| e.into())
    }

    async fn transact<C,R>(&mut self, tid: u16, cmd: C) -> Result<R, Error>
    where
        C: subcmd::SubCmd,
        R: subcmd::SubReply,
    {
        let msg = msg::Transact::new(tid, cmd);
        let reply: reply::Transact<R> = self.command(msg).await?;

        Ok(reply.subcmd)
    }

    async fn negotiate(&mut self) -> Result<reply::ServerSetup, Error> {
        self.command(msg::Negotiate{}).await
    }

    async fn session_setup(&mut self, blob: Bytes)
        -> Result<reply::SessionSetup, Error>
    {
        self.command(msg::SessionSetup::new(blob)).await
    }
}

///
/// Helper function that decodes an SMB URI and returns
/// (host, port, share, path).
///
pub fn resolve_smb_uri(uri: &str) -> Result<(&str, Option<&str>, &str, &str), Error> {
    lazy_static! {
        static ref URI_REGEX: Regex =
            Regex::new(r"smb://(?P<host>\w[\w\.-]*)(:(?P<port>\d+))?/(?P<share>[\w\._-]+)(/(?P<path>.*))?")
                .expect("can't compile URI regex");
    }

    let uri_match = URI_REGEX.captures(uri).ok_or(Error::InvalidUri)?;

    let hostname = uri_match.name("host").ok_or(Error::InvalidUri)?.as_str();
    let maybe_port = uri_match.name("port").map(|m| m.as_str());
    let sharename = uri_match.name("share").ok_or(Error::InvalidUri)?.as_str();
    let pathname = uri_match.name("path").map(|m| m.as_str()).unwrap_or("");

    Ok((hostname, maybe_port, sharename, pathname))
}

#[cfg(test)]
mod tests {
    use super::resolve_smb_uri;

    #[test]
    fn test_uri() {
        let uri = "smb://localhost/myshare/this/is/a/path";
        let (host, port, share, path) = resolve_smb_uri(uri).unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, None);
        assert_eq!(share, "myshare");
        assert_eq!(path, "this/is/a/path");

        let uri = "smb://www.example.org:31337/foo";
        let (host, port, share, path) = resolve_smb_uri(uri).unwrap();
        assert_eq!(host, "www.example.org");
        assert_eq!(port, Some("31337"));
        assert_eq!(share, "foo");
        assert_eq!(path, "");

        let uri = "smb://127.0.0.1:445/share/foo";
        let (host, port, share, path) = resolve_smb_uri(uri).unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, Some("445"));
        assert_eq!(share, "share");
        assert_eq!(path, "foo");
    }
}
