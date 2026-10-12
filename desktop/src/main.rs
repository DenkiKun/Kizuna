mod protocol;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Kizuna desktop v{}", env!("CARGO_PKG_VERSION"));
    // TODO: descoberta mDNS, servidor TLS, emparelhamento
    Ok(())
}
