/// Hacky implementation of the NTLM Authentication Protocol and Security
/// Support Provider.

mod buffer;
mod packet;
mod auth;


use std::io::{self, Read};
use std::fmt;

use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use self::packet::Packet;
use self::buffer::Buffer;
use self::auth::Auth;



#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    InvalidPacket,
    InputParameter,
    NeedChallenge,
    NeedAuth,
    NeedWorkstation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IO(ioerr) => write!(f, "io error: {}", ioerr),
            Error::InvalidPacket => write!(f, "invalid packet data"),
            Error::InputParameter => write!(f, "invalid input paramater"),
            Error::NeedChallenge => write!(f, "need to parse challenge before creating authentication"),
            Error::NeedAuth => write!(f, "authentication not configured"),
            Error::NeedWorkstation => write!(f, "workstation is needed for authentication"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(_err: std::num::TryFromIntError) -> Self {
        Error::InputParameter
    }
}


const NTLMSSP_MAGIC: &[u8] = b"NTLMSSP\0";
const NTLM_MSG_INIT: u32 = 1;
const NTLM_MSG_CHALLENGE: u32 = 2;
const NTLM_MSG_RESPONSE: u32 = 3;
const NTLM_REVISION: u8 = 15;


bitflags! {
    pub struct Flags: u32 {
        const UNICODE = 0x00000001;
        const OEM = 0x00000002;
        const REQUEST_TARGET = 0x00000004;
        const SIGN = 0x00000010;
        const SEAL = 0x00000020;
        const DATAGRAM = 0x00000040;
        const LMKEY = 0x00000080;
        const NETWARE = 0x00000100;
        const NTLM = 0x00000200;
        const NT_ONLY = 0x00000400;
        const ANONYMOUS = 0x00000800;
        const DOMAIN_SUPPLIED = 0x00001000;
        const WORKSTATION_SUPPLIED = 0x00002000;
        const LOCAL = 0x00004000;
        const ALWAYS_SIGN = 0x00008000;
        const TARGET_TYPE_DOMAIN = 0x00010000;
        const TARGET_TYPE_SERVER = 0x00020000;
        const TARGET_TYPE_SHARE = 0x00040000;
        const NTLM2_KEY = 0x00080000;
        const REQ_INIT_RESP = 0x00100000;
        const REQ_ACCEPT_RESP = 0x00200000;
        const REQ_NONNT_KEY = 0x00400000;
        const TARGET_INFO = 0x00800000;
        const VERSION = 0x02000000;
        const BIT128 = 0x20000000;
        const KEY_EXCHANGE = 0x40000000;
        const BIT56 = 0x80000000;
    }
}

impl Flags {
    fn read(stream: &mut impl io::Read) -> io::Result<Self> {
        let bits = stream.read_u32::<LittleEndian>()?;
        Ok(Flags::from_bits_truncate(bits))
    }
}

struct Version {
    major: u8,
    minor: u8,
    build: u16,
}

impl Version {
    fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut stream = io::Cursor::new(Vec::new());
        stream.write_u8(self.major)?;
        stream.write_u8(self.minor)?;
        stream.write_u16::<LittleEndian>(self.build)?;
        stream.write_u8(0)?;
        stream.write_u8(0)?;
        stream.write_u8(0)?;
        stream.write_u8(NTLM_REVISION)?;
        Ok(stream.into_inner())
    }
}


#[derive(Debug)]
pub struct Challenge {
    pub target: String,
    pub flags: Flags,
    pub challenge: [u8; 8],
    pub info: Vec<u8>,
}


impl Challenge {
    pub fn parse(msg: &[u8]) -> Result<Self, Error> {
        let mut cursor = io::Cursor::new(msg);

        // check magic
        let mut magic = [0; 8];
        cursor.read_exact(&mut magic)?;
        if magic != NTLMSSP_MAGIC {
            return Err(Error::InvalidPacket);
        }

        // check msg type
        let msgtype = cursor.read_u32::<LittleEndian>()?;
        if msgtype != NTLM_MSG_CHALLENGE {
            return Err(Error::InvalidPacket);
        }

        let target_buffer = Buffer::read(&mut cursor)?;
        let flags = Flags::read(&mut cursor)?;

        // extract 8 bytes challenge (this is what we really want)
        let mut challenge = [0; 8];
        cursor.read_exact(&mut challenge)?;

        // 8 bytes context, we ignore this
        let mut _context = [0; 8];
        cursor.read_exact(&mut _context)?;

        let info_buffer = Buffer::read(&mut cursor)?;

        // now extract buffers
        let target = target_buffer.extract_string(msg, flags.contains(Flags::UNICODE))?;
        let info = Vec::from(info_buffer.extract(msg)?);

        Ok(Challenge { target, flags, challenge, info })
    }
}


pub struct NTLM {
    flags: Flags,
    auth: Option<Auth>,
    workstation: Option<String>,
    version: Option<Version>,
    challenge: Option<Challenge>,
}

impl NTLM {
    pub fn new() -> Self {
        NTLM {
            flags: Flags::empty(),
            auth: None,
            workstation: None,
            version: None,
            challenge: None,
        }
    }

    pub fn set_flags(&mut self, flags: Flags) {
        self.flags = flags;
    }

    pub fn set_auth(&mut self, user: &str, domain: &str, pass: &str) {
        self.auth = Some(Auth::new(user, domain, pass));
    }

    pub fn set_workstation(&mut self, workstation: &str) {
        self.workstation = Some(workstation.to_owned());
    }

    pub fn set_version(&mut self, major: u8, minor: u8, build: u16) {
        self.version = Some(Version { major, minor, build });
    }

    pub fn create_initialize_msg(&self, stream: &mut impl io::Write) -> Result<(), Error> {
        let mut packet = Packet::new();

        packet.append_binary(NTLMSSP_MAGIC);
        packet.append_u32(NTLM_MSG_INIT);
        packet.append_u32(self.flags.bits());

        if let Some(auth) = self.auth.as_ref() {
            packet.append_buffer(auth.domain.as_bytes());
        }
        if let Some(workstation) = self.workstation.as_ref() {
            packet.append_buffer(workstation.as_bytes());
        }
        if let Some(version) = self.version.as_ref() {
            packet.append_binary(version.as_bytes()?.as_ref());
        }

        packet.write(stream)
    }


    pub fn parse_challenge_msg(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.challenge = Some(Challenge::parse(msg)?);
        Ok(())
    }


    pub fn create_authenticate_msg(&self, stream: &mut impl io::Write) -> Result<(), Error> {
        let challenge = self.challenge
                            .as_ref()
                            .ok_or(Error::NeedChallenge)?;

        let auth = self.auth
                       .as_ref()
                       .ok_or(Error::NeedAuth)?;

        let workstation = self.workstation
                              .as_ref()
                              .ok_or(Error::NeedWorkstation)?;

        let (_sk, response) = auth.response(challenge)?;

        let mut packet = Packet::new();

        packet.append_binary(NTLMSSP_MAGIC);
        packet.append_u32(NTLM_MSG_RESPONSE);
        packet.append_buffer(&[0u8; 24]);                   // Empty LM Response
        packet.append_buffer(&response);                    // NTLMv2 Response
        packet.append_buffer(auth.domain.as_bytes());
        packet.append_buffer(auth.user.as_bytes());
        packet.append_buffer(workstation.as_bytes());

        // optional stuff
        //packet.append_buffer(&sk);
        //packet.append_u32(self.flags.bits());
        //if let Some(version) = self.version.as_ref() {
        //    packet.append_binary(version.as_bytes()?.as_ref());
        //}

        packet.write(stream)
    }
}


#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use hex_literal::hex;
    use super::*;

    #[test]
    fn test_create_init() {
        /*
         * Generate message type 1 example from
         * http://davenport.sourceforge.net/ntlm.html
         */

        let mut ntlm = NTLM::new();

        ntlm.set_flags(Flags::UNICODE
                     | Flags::OEM
                     | Flags::REQUEST_TARGET
                     | Flags::NTLM
                     | Flags::DOMAIN_SUPPLIED
                     | Flags::WORKSTATION_SUPPLIED
        );

        ntlm.set_auth("user", "DOMAIN", "SecREt01");
        ntlm.set_workstation("WORKSTATION");
        ntlm.set_version(5, 0, 2195);

        let mut buffer = Cursor::new(Vec::new());
        ntlm.create_initialize_msg(&mut buffer).expect("error writing ntlm init message");

        /* i swapped positions of domain and workstation data */
        let expected = hex!("4e544c4d53535000010000000732000006000600280000000b000b002e000000"
                            "050093080000000f444f4d41494e574f524b53544154494f4e");

        assert_eq!(buffer.into_inner(), expected);
    }


    #[test]
    fn test_read_challenge() {
        let msg_challenge = hex!("4e544c4d53535000020000000c000c003000000001028100"
                                 "0123456789abcdef0000000000000000620062003c000000"
                                 "44004f004d00410049004e0002000c0044004f004d004100"
                                 "49004e0001000c0053004500520056004500520004001400"
                                 "64006f006d00610069006e002e0063006f006d0003002200"
                                 "7300650072007600650072002e0064006f006d0061006900"
                                 "6e002e0063006f006d0000000000");


        let mut ntlm = NTLM::new();
        ntlm.parse_challenge_msg(&msg_challenge)
            .expect("can't read ntlm challenge");

        let challenge = ntlm.challenge.unwrap();

        assert_eq!(challenge.flags, Flags::UNICODE
                                  | Flags::NTLM
                                  | Flags::TARGET_TYPE_DOMAIN
                                  | Flags::TARGET_INFO);

        assert_eq!(challenge.target, "DOMAIN");
        assert_eq!(challenge.challenge, hex!("0123456789abcdef"));
        assert_eq!(challenge.info, hex!("02000c0044004f004d00410049004e00"
                                        "01000c00530045005200560045005200"
                                        "0400140064006f006d00610069006e00"
                                        "2e0063006f006d000300220073006500"
                                        "72007600650072002e0064006f006d00"
                                        "610069006e002e0063006f006d000000"
                                        "0000"));
    }
}
