use core::convert::Infallible;
use core::fmt;

use s2n_quic::provider::tls::Provider;

use crate::tls::null::Endpoint;

#[derive(Debug)]
pub struct NullTls<T = ()>(Option<T>);

impl<T> NullTls<T> {
    pub fn new(ctx: Option<T>) -> Self {
        Self(ctx)
    }
}

impl Default for NullTls {
    fn default() -> Self {
        Self(None)
    }
}

impl<T> Provider for NullTls<T>
where
    T: fmt::Debug + Send + Clone + 'static,
{
    type Server = Endpoint<T>;
    type Client = Endpoint<T>;
    type Error = Infallible;

    fn start_server(self) -> Result<Self::Server, Self::Error> {
        Ok(Endpoint::new(self.0))
    }

    fn start_client(self) -> Result<Self::Client, Self::Error> {
        Ok(Endpoint::new(self.0))
    }
}
