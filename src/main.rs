use std::error::Error;
use tracing::info;

mod acme;

use acme::{Directory, MemoryPersist};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    tracing_subscriber::fmt::init();
    info!("Started runtime");

    let memory = MemoryPersist::new();
    let dir = Directory::from_url::<MemoryPersist>(Directory::LE_STAGING, memory)
        .await
        .unwrap();
    let account = dir.account(true, "test@test.ch").await?;
    println!("{:?}", account);

    Ok(())
}
