use bytes::{Bytes, Buf};

use crate::utils;
use crate::smb::Error;
use crate::smb::info::Cmd;
use crate::smb::reply::{Reply, ReplyCtx};

/// Reply to SMB_COM_TRANSACTION2, see 2.2.4.46.2
pub(crate) struct Transact2 {
    pub parameter: Bytes,
    pub parameter_total: usize,

    pub data: Bytes,
    pub data_total: usize,
}

impl Reply for Transact2 {
    const CMD: Cmd = Cmd::Transact2;
    const ANDX: bool = false;

    fn create(mut ctx: ReplyCtx) -> Result<Self, Error> {
        // parameter
        let total_parameter_count = ctx.parameter.get_u16_le() as usize;
        let total_data_count = ctx.parameter.get_u16_le() as usize;
        ctx.parameter.advance(2);   // reserved

        let parameter_count = ctx.parameter.get_u16_le() as usize;
        let parameter_offset = utils::try_sub(ctx.parameter.get_u16_le().into(), ctx.data_offset)
            .ok_or(Error::InvalidData)?;
        ctx.parameter.advance(2);   // ignoring parameter displacement

        let data_count = ctx.parameter.get_u16_le() as usize;
        let data_offset = utils::try_sub(ctx.parameter.get_u16_le().into(), ctx.data_offset)
            .ok_or(Error::InvalidData)?;
        ctx.parameter.advance(2);   // ignoring data displacement

        // data
        let sub_parameter = ctx.data.slice(parameter_offset..parameter_offset+parameter_count);
        let sub_data = ctx.data.slice(data_offset..data_offset+data_count);

        let reply = Self {
            parameter: sub_parameter,
            parameter_total: total_parameter_count,

            data: sub_data,
            data_total: total_data_count,
        };

        Ok(reply)
    }
}
