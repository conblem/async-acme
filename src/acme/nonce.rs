use hyper::{Body, Client, Request};
use hyper::header::HeaderName;
use tokio::sync::mpsc;

use super::{HTTPSConnector, Header};

const REPLAY_NONCE_HEADER: &str = "replay-nonce";

struct NoncePool {
    client: Client<HTTPSConnector>,
    url: String,
    replay_nonce_header: HeaderName,
}

impl NoncePool {
    fn new(client: Client<HTTPSConnector>, url: String) -> Self {
        let (sender, receiver) = mpsc::channel::<()>(64);
        Self {
            client,
            url,
            replay_nonce_header: HeaderName::from_static(REPLAY_NONCE_HEADER),
        }
    }
    async fn get_nonce(&self) -> Result<Header, ()> {
        let req = Request::head(&self.url).body(Body::empty()).map_err(|_| ())?;
        let mut res = self.client.request(req).await.map_err(|_| ())?;

        res.headers_mut()
            .remove(&self.replay_nonce_header)
            .map(Header)
            .ok_or_else(|| ())
    }
}
