//! A minimal QUIC client that talks to `examples/echo_server.rs`.
//!
//! The message is read from stdin, so it can be piped:
//!
//! ```sh
//! echo "hello, quicless" | cargo run --example echo_client -- 127.0.0.1:4433
//! ```
//!
//! The client opens a bidirectional stream, sends the message, waits for the
//! echo, and checks that it round-tripped intact.

use std::io::{read_to_string, stdin};

use bytes::Bytes;
use quicless::provider::null::NullTls;

use s2n_quic::{Client, client::Connect};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:4433".to_string());
    let message = read_to_string(stdin())?;

    let mut client = Client::builder().with_tls(NullTls::default())?.with_io("0.0.0.0:0")?.start()?;

    let remote: std::net::SocketAddr = addr.parse()?;
    // The transport requires a server name, but the null endpoint discards it:
    // it reports an empty name on both ends and never puts it on the wire.
    let mut connection = client.connect(Connect::new(remote).with_server_name("")).await?;

    let mut stream = connection.open_bidirectional_stream().await?;

    // Send the payload and signal that we are done sending.
    stream.send(Bytes::from(message.clone())).await?;
    stream.finish()?;

    // Collect the echo until the server closes its send half.
    let mut echoed = Vec::new();
    while let Some(chunk) = stream.receive().await? {
        echoed.extend_from_slice(&chunk);
    }

    let echoed = String::from_utf8(echoed)?;

    if echoed != message {
        return Err("echoed message did not match what was sent".into());
    }

    println!("{}", echoed);

    // Dropping the last handle closes the connection with a transport level
    // `NO_ERROR`. The endpoint still has to *transmit* that CONNECTION_CLOSE, so
    // `wait_idle` keeps the runtime alive until it has been flushed. Without it
    // the process exits first and the peer only notices 30 seconds later, when
    // its idle timeout expires.
    drop(stream);
    drop(connection);
    client.wait_idle().await?;

    Ok(())
}
