use tracing::info;

mod acme;

use acme::{Directory, MemoryPersist};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Started runtime");

    let memory = MemoryPersist::new();
    let dir = Directory::from_url::<MemoryPersist>(Directory::LE_STAGING, memory)
        .await
        .unwrap();
    let account = dir.new_account(true).await.unwrap();
    let account = dir.new_account(true).await.unwrap();
    println!("{:?}", account);
}
