use bytes::Buf;

use crate::utils;
use crate::smb::Error;
use crate::smb::info::Cmd;
use crate::smb::reply::{Reply, ReplyCtx};
use super::SubReply;

/// Reply to SMB_COM_TRANSACTION2, see 2.2.4.46.2
pub(crate) struct Transact2<T> {
    pub subcmd: T,
}

impl<T: SubReply> Reply for Transact2<T> {
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


        // FIXME we need to support incomplete transact2 replies
        if parameter_count < total_parameter_count || data_count < total_data_count {
            return Err(Error::Unsupported("transaction2 reply split to multiple packets".to_owned()));
        }

        // data
        let sub_parameter = ctx.data.slice(parameter_offset..parameter_offset+parameter_count);
        let sub_data = ctx.data.slice(data_offset..data_offset+data_count);

        // create sub-command response
        let subcmd = T::parse(sub_parameter, sub_data)?;

        Ok(Transact2::<T> { subcmd })
    }
}



