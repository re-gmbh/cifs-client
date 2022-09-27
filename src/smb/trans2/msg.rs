use bytes::{BytesMut, BufMut};

use crate::utils;
use crate::smb::Error;
use crate::smb::msg::Msg;
use crate::smb::info::{Cmd, Info};
use crate::smb::common::SMB_HEADER_LEN;
use super::SubCmd;

/// Parameter for SMB_COM_TRANSACTION2 (0x32), see 2.2.4.46.
/// This is actually very similar to Transact<T> above.
pub(crate) struct Transact2<T> {
    tid: u16,
    subcmd: T,
}

impl<T: SubCmd> Transact2<T> {
    pub(crate) fn new(tid: u16, subcmd: T) -> Self {
        Self {
            tid,
            subcmd,
        }
    }
}

impl<T: SubCmd> Msg for Transact2<T> {
    const CMD: Cmd = Cmd::Transact2;
    const ANDX: bool = false;

    fn fix_header(&self, info: &mut Info)  {
        info.tid = self.tid;
    }

    fn body(&self, _info: &Info, parameter: &mut BytesMut, data: &mut BytesMut)
        -> Result<(), Error>
    {
        // serialize sub command
        let sub_parameter = self.subcmd.parameter()?;
        let sub_parameter_len: u16 = sub_parameter.len()
            .try_into()
            .map_err(|_| Error::CreatePacket("parameter transaction2 sub-command is too large".to_owned()))?;

        let sub_data = self.subcmd.data()?;
        let sub_data_len: u16 = sub_data.len()
            .try_into()
            .map_err(|_| Error::CreatePacket("data of transaction2 sub-command is too large".to_owned()))?;

        // position of data relative to SMB header
        let data_start = SMB_HEADER_LEN + 1 + 30 + 2;

        // sub parameter start at the first 32bit-aligned position in data
        let sub_parameter_offset = utils::round_up_4n(data_start + 1);

        // sub data start at the next 32bit-aligned position after sub parameter
        let sub_data_offset = utils::round_up_4n(sub_parameter_offset + sub_parameter.len());



        // parameter

        // the following are 'total counts' and are important if the
        // subcommand is split into multiple messages (in that case
        // parameter_count would be smaller than total_parameter_count)
        // but we only send one message so this is the same as below.
        parameter.put_u16_le(sub_parameter_len);
        parameter.put_u16_le(sub_data_len);

        parameter.put_u16_le(T::MAX_PARAM_COUNT);
        parameter.put_u16_le(T::MAX_DATA_COUNT);
        parameter.put_u8(T::MAX_SETUP_COUNT);
        parameter.put_u8(0);                // reserved

        parameter.put_u16_le(0);            // flags
        parameter.put_u32_le(0);            // timeout
        parameter.put_u16_le(0);            // reserved

        parameter.put_u16_le(sub_parameter_len);
        parameter.put_u16_le(sub_parameter_offset.try_into().expect("parameter offset too big"));

        parameter.put_u16_le(sub_data_len);
        parameter.put_u16_le(sub_data_offset.try_into().expect("data offset too big"));

        parameter.put_u8(1);                // setup for trans2 subcmds seems to be always 1 word
        parameter.put_u8(0);                // reserved
        parameter.put_u16_le(T::SETUP);     // the setup


        // data
        data.put_u8(0);                     // name, always 0
        data.put_bytes(0, utils::fill_up_4n(data_start + data.len()));
        data.put(sub_parameter);
        data.put_bytes(0, utils::fill_up_4n(data_start + data.len()));
        data.put(sub_data);

        Ok(())
    }
}
