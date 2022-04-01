use rand::{RngCore, rngs::OsRng};
use hex_literal::hex;
use bytes::{Bytes, BytesMut, BufMut};

use crate::utils;
use super::{Error, ChallengeMsg};


#[derive(Debug, Clone)]
pub struct Auth {
    pub user: String,
    pub workstation: String,
    pub domain: String,
    pub password: String,
}

impl Auth {
    pub fn new(user: &str, workstation: &str, domain: &str, password: &str) -> Self {
        Auth {
            user: user.to_owned(),
            workstation: workstation.to_owned(),
            domain: domain.to_owned(),
            password: password.to_owned(),
        }
    }

    /// Hash like we are in the 90s, using windows and maybe took something
    /// illegal. Please understand that this is possibly the worst password
    /// hash ever devised!
    fn ntlm_hash(&self) -> [u8; 16] {
        let unicoded = utils::encode_utf16le(&self.password);
        utils::md4_oneshot(&unicoded)
    }

    /// Version 2 is still pretty stupid..
    fn ntlmv2_hash(&self) -> [u8; 16] {
        let key = self.ntlm_hash();
        let data = utils::encode_utf16le(&(self.user.to_uppercase() + &self.domain));

        utils::hmac_md5_oneshot(&key, &data)
    }

    pub fn authenticate(&self, challenge_msg: &ChallengeMsg) -> Result<([u8; 16], Bytes), Error> {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);

        // generate blob
        let mut blob = BytesMut::with_capacity(1024);
        blob.put(hex!("0101000000000000").as_slice());
        blob.put_u64_le(utils::get_windows_time());
        blob.put(random.as_slice());
        //blob.put(hex!("0090d336b734c301").as_slice()); // XXX fake time
        //blob.put(hex!("ffffff0011223344").as_slice()); // XXX fake random
        blob.put_u32_le(0);
        blob.extend_from_slice(&challenge_msg.info[..]);
        blob.put_u32_le(0);


        let mut data = BytesMut::with_capacity(challenge_msg.challenge.len() + blob.len());
        data.put(&challenge_msg.challenge[..]);
        data.put(&blob[..]);

        let key = self.ntlmv2_hash();
        let tag = utils::hmac_md5_oneshot(&key, &data);
        let sk = utils::hmac_md5_oneshot(&key, &tag);

        let mut result = BytesMut::with_capacity(tag.len() + blob.len());
        result.put(tag.as_slice());
        result.put(blob);

        Ok((sk, result.freeze()))
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    #[test]
    fn ntlm_hash() {
        let auth = Auth::new("user", "workstation", "DOMAIN", "SecREt01");
        let hash = auth.ntlm_hash();

        assert_eq!(hash, hex!("cd06ca7c7e10c99b1d33b7485a2ed808"));
    }

    #[test]
    fn ntlmv2_hash() {
        let auth = Auth::new("user", "workstation", "DOMAIN", "SecREt01");
        let hash = auth.ntlmv2_hash();

        assert_eq!(hash, hex!("04b8e0ba74289cc540826bab1dee63ae"));
    }

    /*
    #[test]
    fn challenge_response() {
        let msg_challenge = Bytes::from(hex!(
                "4e544c4d53535000020000000c000c003000000001028100"
                "0123456789abcdef0000000000000000620062003c000000"
                "44004f004d00410049004e0002000c0044004f004d004100"
                "49004e0001000c0053004500520056004500520004001400"
                "64006f006d00610069006e002e0063006f006d0003002200"
                "7300650072007600650072002e0064006f006d0061006900"
                "6e002e0063006f006d0000000000").as_ref());

        let challenge = ChallengeMsg::parse(&msg_challenge)
            .expect("can't parse NTLM challenge");


        let auth = Auth::new("user", "WORKSTATION", "DOMAIN", "SecREt01");
        let (_, response) = auth.authenticate(&challenge)
                                .expect("can't authenticate challenge");

        assert_eq!(&response[..], hex!("cbabbca713eb795d04c97abc01ee4983"
                                  "01010000000000000090d336b734c301"
                                  "ffffff00112233440000000002000c00"
                                  "44004f004d00410049004e0001000c00"
                                  "53004500520056004500520004001400"
                                  "64006f006d00610069006e002e006300"
                                  "6f006d00030022007300650072007600"
                                  "650072002e0064006f006d0061006900"
                                  "6e002e0063006f006d00000000000000"
                                  "0000"));
    }
    */
}
