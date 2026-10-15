//! GammaCloud development guest service entrypoint.
mod dev_vsock;
mod manager;
mod product;
mod security;
mod server;

fn main() -> std::io::Result<()> {
    server::serve()
}
