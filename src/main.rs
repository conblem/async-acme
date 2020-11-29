use tracing::info;

mod acme;

use acme::Directory;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Started runtime");

    let dir = Directory::from_url(Directory::LE_STAGING).await.unwrap();
}
