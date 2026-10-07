# Quicless

Suites for QUIC transmission as an alternative to SCTP.

`quicless` provides a *null* TLS endpoint for [`s2n-quic`](https://crates.io/crates/s2n-quic).
It performs no handshake and no encryption: the two peers simply exchange their
QUIC transport parameters in the clear and move straight to 1-RTT. That makes it
useful for benchmarking and testing the transport itself, with crypto factored
out.

> **Warning**
>
> There is no confidentiality, integrity or authenticity whatsoever. Anyone on
> the path can read, forge and replay everything. Use it on a trusted network or
> loopback.

## Import

```bash
cargo add quicless
```

## Usage

Hand the null endpoint to a `Client` or `Server` through the `provider` feature
(enabled by default):

```rust
use quicless::provider::null::NullTls;
use s2n_quic::Server;

let mut server = Server::builder()
    .with_tls(NullTls::default())?
    .with_io("127.0.0.1:4433")?
    .start()?;
```

`NullTls` also accepts an application context that is cloned into every server
session, where it can be taken back out with
[`Connection::take_tls_context`](https://docs.rs/s2n-quic/latest/s2n_quic/connection/struct.Handle.html#method.take_tls_context):

```rust
use quicless::provider::null::NullTls;

// the context can be any Send + Clone + Debug + 'static value
let tls = NullTls::new(Some("tenant-a"));

// in the connection handler
let context = connection.take_tls_context();
let tenant = context.and_then(|ctx| ctx.downcast::<&'static str>().ok());
```

If you only want the endpoint and drive `s2n-quic-transport` yourself, disable
default features and use `quicless::tls::null::Endpoint` directly.

## Echo server & client

The repository ships a matching pair of examples. Start the server:

```bash
cargo run --example echo_server -- 127.0.0.1:4433
```

Then run the client; the message is read from stdin, so it can be piped. See
[`examples/echo_server.rs`](examples/echo_server.rs) and
[`examples/echo_client.rs`](examples/echo_client.rs) for the full sources.

```bash
echo "hello, quicless" | cargo run --example echo_client -- 127.0.0.1:4433
# hello, quicless
```

The client opens a bidirectional stream, sends the message, half-closes with a
FIN, and checks that the bytes it reads back match. Every byte received on a
stream is echoed back by the server.

## Features

| feature    | default | description                                                     |
| ---------- | ------- | --------------------------------------------------------------- |
| `provider` | yes     | `quicless::provider`, the adapter for the `s2n-quic` endpoint API |

The `provider` feature pulls in `s2n-quic` (and, through it, `rustls`). That is
necessary because `s2n-quic` does not compile unless exactly one of its own TLS
provider features is enabled, even when the endpoint is immediately replaced by
the null one. The chosen backend is never started: `with_tls` swaps it out before
`start()`. Use `--no-default-features` if you want the endpoint without any of
that.

`s2n-quic` is pinned to `=1.88.0`, matching the `s2n-quic-core` version above.
`1.89` depends on `s2n-quic-core 0.89`, and the endpoint would not satisfy its
trait bounds.

## Behaviour

What differs from a real TLS provider, beyond the missing crypto:

| accessor | value |
| --- | --- |
| `Connection::server_name()` | always `Some("")`. The name passed to `Connect::with_server_name(..)` is required by the transport but discarded by this endpoint: there is no ClientHello to carry an SNI, so nothing is forwarded and nothing is validated. |
| `Connection::application_protocol()` | a single NUL byte (`b"\0"`), used as a placeholder ALPN. |
| key exchange group | reported as `null_group`. |
| `Connection::take_tls_context()` | the value passed to `NullTls::new`, cloned per server session. |

### Closing connections

The examples close with an explicit drop plus
[`Client::wait_idle`](https://docs.rs/s2n-quic/latest/s2n_quic/client/struct.Client.html#method.wait_idle):

```rust
drop(stream);
drop(connection);
client.wait_idle().await?;
```

Dropping the last handle only *marks* the connection for closing - the endpoint
still has to transmit the `CONNECTION_CLOSE` frame. If the process exits first,
the frame never leaves and the peer keeps the connection until its idle timeout
(30 seconds by default). `wait_idle` keeps the runtime alive until it is flushed.

## Credits

`src/tls/null.rs` is derived from the null TLS endpoint shipped with
[aws/s2n-quic](https://github.com/aws/s2n-quic), Copyright Amazon.com, Inc. or
its affiliates. The SPDX headers are kept in the source files; see
[NOTICE](NOTICE).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
