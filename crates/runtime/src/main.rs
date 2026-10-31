//! GammaCloud development guest service entrypoint.
mod attestation;
mod dev_vsock;
mod identity;
mod manager;
mod product;
mod security;
mod server;
mod session;
mod workspace;

fn main() -> std::io::Result<()> {
    server::serve()
}
