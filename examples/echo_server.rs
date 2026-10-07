//! A minimal QUIC echo server backed by `quicless`'s null TLS endpoint.
//!
//! Run it with:
//!
//! ```sh
//! cargo run --example echo_server -- 127.0.0.1:4433
//! ```
//!
//! Every byte received on a bidirectional stream is sent back to the peer.

use quicless::provider::null::NullTls;

use s2n_quic::{Server, connection::Connection, stream::BidirectionalStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:4433".to_string());

    let mut server = Server::builder().with_tls(NullTls::default())?.with_io(addr.as_str())?.start()?;

    println!("echo server listening on {}", server.local_addr()?);

    while let Some(connection) = server.accept().await {
        tokio::spawn(async move {
            if let Err(error) = handle_connection(connection).await {
                eprintln!("connection failed: {error}");
            }
        });
    }

    Ok(())
}

async fn handle_connection(mut connection: Connection) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("accepted connection from {}", connection.remote_addr()?);

    while let Some(stream) = connection.accept_bidirectional_stream().await? {
        tokio::spawn(async move {
            if let Err(error) = echo(stream).await {
                eprintln!("stream failed: {error}");
            }
        });
    }

    println!("connection closed");

    Ok(())
}

/// Copies everything received on `stream` back to the peer until the stream is
/// finished, then closes our send half with a FIN.
async fn echo(mut stream: BidirectionalStream) -> Result<(), s2n_quic::stream::Error> {
    while let Some(data) = stream.receive().await? {
        stream.send(data).await?;
    }

    stream.finish()?;

    Ok(())
}
