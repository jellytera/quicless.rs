// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal endpoint that doesn't perform any handshakes or encryption
//!
//! NOTE: this should only be used for internal testing
//!
//! The main purpose of this endpoint type is to identify bottlenecks in the code _outside_ of
//! crypto, since that's a large portion of the cycles we use. This has similar goals to the
//! proposal in https://datatracker.ietf.org/doc/html/draft-banks-quic-disable-encryption-00, but
//! instead reduces the handshake to simply exchanging transport parameters.

use bytes::Bytes;
use core::{any::Any, mem::size_of, task::Poll};
use s2n_quic_core::{
    application::ServerName,
    crypto::{self, tls},
    transport,
};

/// The null endpoint reports no server name: it performs no TLS handshake, so
/// there is no ClientHello to carry a Server Name Indication, and the name the
/// client configured is discarded rather than forwarded or validated.
static EMPTY_SERVER_NAME: ServerName = ServerName::from_static("");

#[derive(Debug)]
pub struct Endpoint<T = ()>(Option<T>);
impl<T> Endpoint<T> {
    pub fn new(ctx: Option<T>) -> Self {
        Endpoint(ctx)
    }
}
impl<T> Default for Endpoint<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<T: Send + Clone + 'static + std::fmt::Debug> crypto::tls::Endpoint for Endpoint<T> {
    type Session = Session<T>;

    #[inline]
    fn new_server_session<Params: s2n_codec::EncoderValue>(&mut self, transport_parameters: &Params, _connection_info: tls::ConnectionInfo) -> Self::Session {
        let params = transport_parameters.encode_to_vec().into();
        Session::Server(server::TlsSession::Init { transport_parameters: params, ctx: self.0.clone() })
    }

    #[inline]
    fn new_client_session<Params: s2n_codec::EncoderValue>(&mut self, transport_parameters: &Params, _server_name: ServerName) -> Self::Session {
        let params = transport_parameters.encode_to_vec().into();
        Session::Client(client::Session::Init { transport_parameters: params })
    }

    #[inline]
    fn max_tag_length(&self) -> usize {
        0
    }
}

#[derive(Debug)]
pub enum Session<T> {
    Client(client::Session<T>),
    Server(server::TlsSession<T>),
}

impl<T> crypto::CryptoSuite for Session<T> {
    type HandshakeKey = key::NoCrypto;
    type HandshakeHeaderKey = key::NoCrypto;
    type InitialKey = key::NoCrypto;
    type InitialHeaderKey = key::NoCrypto;
    type OneRttKey = key::NoCrypto;
    type OneRttHeaderKey = key::NoCrypto;
    type ZeroRttKey = key::NoCrypto;
    type ZeroRttHeaderKey = key::NoCrypto;
    type RetryKey = key::NoCrypto;
}

impl<T: std::fmt::Debug + Send + Clone + 'static> tls::Session for Session<T> {
    #[inline]
    fn poll<C: tls::Context<Self>>(&mut self, context: &mut C) -> Poll<Result<(), transport::Error>> {
        match self {
            Self::Client(session) => session.poll(context),
            Self::Server(session) => session.poll(context),
        }
    }

    #[inline]
    fn parse_hello(_msg_type: tls::HandshakeType, _header_chunk: &[u8], _total_received_len: u64, _max_hello_size: u64) -> Result<Option<tls::HelloOffsets>, s2n_quic_core::transport::Error> {
        let offsets = tls::HelloOffsets { payload_offset: 0, payload_len: 0 };
        Ok(Some(offsets))
    }
}

static FIN: Bytes = Bytes::from_static(&[0]);
static NULL: Bytes = Bytes::from_static(&[0]);

pub mod client {
    use super::*;
    use core::marker::PhantomData;
    use s2n_quic_core::crypto::tls::NamedGroup;

    #[derive(Debug)]
    pub enum Session<T> {
        Init { transport_parameters: Bytes },
        WaitingInitial {},
        WaitingHandshake { params: Bytes },
        Complete,
        _PH(PhantomData<T>),
    }

    impl<T> Session<T> {
        #[inline]
        pub fn poll<C: tls::Context<super::Session<T>>>(&mut self, context: &mut C) -> Poll<Result<(), transport::Error>> {
            loop {
                match self {
                    Self::Init { transport_parameters } => {
                        context.send_initial(core::mem::take(transport_parameters));

                        context.on_server_name(EMPTY_SERVER_NAME.clone())?;

                        *self = Self::WaitingInitial {};
                    }
                    Self::WaitingInitial {} => {
                        let params = match context.receive_initial(None) {
                            Some(bytes) => bytes,
                            None => return Poll::Pending,
                        };

                        context.on_handshake_keys(key::NoCrypto, key::NoCrypto)?;

                        // notify the server we're done
                        context.send_handshake(FIN.clone());

                        *self = Self::WaitingHandshake { params };
                    }
                    Self::WaitingHandshake { params } => {
                        if context.receive_handshake(None).is_none() {
                            return Poll::Pending;
                        }

                        context.on_application_protocol(NULL.clone())?;
                        context.on_key_exchange_group(NamedGroup { group_name: "null_group", contains_kem: false })?;

                        context.on_one_rtt_keys(key::NoCrypto, key::NoCrypto, tls::ApplicationParameters { transport_parameters: params })?;

                        context.on_handshake_complete()?;

                        *self = Self::Complete;

                        return Ok(()).into();
                    }
                    Self::Complete => return Ok(()).into(),
                    _ => unreachable!(),
                }
            }
        }
    }
}

pub mod server {
    use super::*;
    use s2n_quic_core::crypto::tls::NamedGroup;

    #[derive(Debug)]
    pub enum TlsSession<T> {
        Init { transport_parameters: Bytes, ctx: Option<T> },
        WaitingComplete,
        Complete,
    }

    impl<T: Send + Clone + 'static> TlsSession<T> {
        #[inline]
        pub fn poll<C: tls::Context<super::Session<T>>>(&mut self, context: &mut C) -> Poll<Result<(), transport::Error>> {
            loop {
                match self {
                    Self::Init { transport_parameters, ctx } => {
                        let client_params = match context.receive_initial(None) {
                            Some(data) => data,
                            None => return Poll::Pending,
                        };
                        context.send_initial(core::mem::take(transport_parameters));

                        context.on_handshake_keys(key::NoCrypto, key::NoCrypto)?;
                        context.send_handshake(FIN.clone());

                        context.on_application_protocol(NULL.clone())?;
                        context.on_key_exchange_group(NamedGroup { group_name: "null_group", contains_kem: false })?;
                        // We just clone and set it, in real user case, you can put anything you want.
                        if let Some(ctx) = ctx {
                            context.on_tls_context(Box::new(ctx.clone()) as Box<dyn Any + Send + 'static>);
                        }

                        // No SNI to report. This is set before `on_one_rtt_keys` so the empty
                        // name is consistently visible in the `HandshakeInfo` that is passed to
                        // the connection limits provider.
                        context.on_server_name(EMPTY_SERVER_NAME.clone())?;

                        context.on_one_rtt_keys(key::NoCrypto, key::NoCrypto, tls::ApplicationParameters { transport_parameters: &client_params })?;

                        *self = Self::WaitingComplete;
                    }
                    Self::WaitingComplete => {
                        if context.receive_handshake(None).is_none() {
                            return core::task::Poll::Pending;
                        }

                        *self = Self::Complete;
                        context.on_handshake_complete()?;

                        return Ok(()).into();
                    }
                    Self::Complete => return Ok(()).into(),
                }
            }
        }
    }
}

mod key {
    use super::*;
    use s2n_quic_core::crypto::scatter;

    #[derive(Debug)]
    pub struct NoCrypto;

    impl crypto::Key for NoCrypto {
        #[inline(always)]
        fn decrypt(&self, _packet_number: u64, _header: &[u8], _payload: &mut [u8]) -> Result<(), crypto::packet_protection::Error> {
            // Do nothing
            Ok(())
        }

        #[inline(always)]
        fn encrypt(&mut self, _packet_number: u64, _header: &[u8], payload: &mut scatter::Buffer) -> Result<(), crypto::packet_protection::Error> {
            // copy any extra bytes into the slice
            payload.flatten();
            Ok(())
        }

        #[inline(always)]
        fn tag_len(&self) -> usize {
            0
        }

        #[inline(always)]
        fn aead_confidentiality_limit(&self) -> u64 {
            u64::MAX
        }

        #[inline(always)]
        fn aead_integrity_limit(&self) -> u64 {
            u64::MAX
        }

        #[inline(always)]
        fn cipher_suite(&self) -> tls::CipherSuite {
            tls::CipherSuite::Unknown
        }
    }

    impl crypto::HandshakeKey for NoCrypto {}

    impl crypto::HeaderKey for NoCrypto {
        #[inline(always)]
        fn opening_header_protection_mask(&self, _ciphertext_sample: &[u8]) -> crypto::HeaderProtectionMask {
            Default::default()
        }

        #[inline(always)]
        fn opening_sample_len(&self) -> usize {
            size_of::<crypto::HeaderProtectionMask>()
        }

        #[inline(always)]
        fn sealing_header_protection_mask(&self, _ciphertext_sample: &[u8]) -> crypto::HeaderProtectionMask {
            Default::default()
        }

        #[inline(always)]
        fn sealing_sample_len(&self) -> usize {
            size_of::<crypto::HeaderProtectionMask>()
        }
    }

    impl crypto::HandshakeHeaderKey for NoCrypto {}

    impl crypto::InitialKey for NoCrypto {
        type HeaderKey = NoCrypto;

        #[inline(always)]
        fn new_server(_connection_id: &[u8]) -> (Self, Self::HeaderKey) {
            (NoCrypto, NoCrypto)
        }

        #[inline(always)]
        fn new_client(_connection_id: &[u8]) -> (Self, Self::HeaderKey) {
            (NoCrypto, NoCrypto)
        }
    }

    impl crypto::InitialHeaderKey for NoCrypto {}

    impl crypto::OneRttKey for NoCrypto {
        #[inline(always)]
        fn derive_next_key(&self) -> Self {
            NoCrypto
        }
    }

    impl crypto::OneRttHeaderKey for NoCrypto {}

    impl crypto::ZeroRttKey for NoCrypto {}

    impl crypto::ZeroRttHeaderKey for NoCrypto {}

    impl crypto::RetryKey for NoCrypto {
        #[inline(always)]
        fn generate_tag(_payload: &[u8]) -> crypto::retry::IntegrityTag {
            Default::default()
        }

        #[inline(always)]
        fn validate(_payload: &[u8], _tag: crypto::retry::IntegrityTag) -> Result<(), crypto::packet_protection::Error> {
            Ok(())
        }
    }
}
