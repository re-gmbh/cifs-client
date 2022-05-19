use bytes::{Bytes, BytesMut, BufMut};

use crate::smb::Error;
use super::reply::Transact2;
use super::SubReply;

/// Collects parameter and data for a Transact2 subcommand.
pub(crate) struct CollectTrans2 {
    parameter: Option<Collect>,
    data: Option<Collect>,
}

impl CollectTrans2 {
    pub(crate) fn new() -> Self {
        Self {
            parameter: None,
            data: None,
        }
    }

    /// adds the given Transact2 msg to the collection. returns true, if
    /// the collection is done.
    pub(crate) fn add(&mut self, msg: Transact2) -> Result<bool, Error> {
        let parameter = self.parameter.get_or_insert(Collect::new(msg.parameter_total));
        parameter.add(msg.parameter, msg.parameter_total)?;

        let data = self.data.get_or_insert(Collect::new(msg.data_total));
        data.add(msg.data, msg.data_total)?;

        Ok(parameter.is_ready() && data.is_ready())
    }


    pub(crate) fn get_subreply<R: SubReply>(self) -> Result<R, Error> {
        let parameter = self.parameter.map_or(Bytes::new(), |b| b.get());
        let data = self.data.map_or(Bytes::new(), |b| b.get());

        let subreply = R::parse(parameter, data)?;

        Ok(subreply)
    }
}


/// Collect is a wrapper around BytesMut, that collects data until
/// a given watermark 'total' is reached.
struct Collect {
    buffer: BytesMut,
    total: usize,
}

impl Collect {
    fn new(total: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(total),
            total,
        }
    }

    fn add(&mut self, data: Bytes, total: usize) -> Result<(), Error> {
        // safety check: if server changes it's mind about total buffer
        // size, we bail!
        if self.total != total {
            return Err(Error::InvalidData);
        }
        if data.len() > self.buffer.remaining_mut() {
            return Err(Error::InvalidData);
        }
        self.buffer.put(data);
        Ok(())
    }

    fn is_ready(&self) -> bool {
        self.buffer.len() >= self.total
    }

    fn get(self) -> Bytes {
        self.buffer.freeze()
    }
}
