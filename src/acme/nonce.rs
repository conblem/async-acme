use hyper;
use hyper::header::HeaderName;
use hyper::http;
use hyper::{Body, Client, Request};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use super::{HTTPSConnector, Header};

const REPLAY_NONCE_HEADER: &str = "replay-nonce";

struct NoncePool {
    sender: mpsc::Sender<oneshot::Sender<Result<Header, NoncePoolError>>>,
}

#[derive(Error, Debug)]
pub enum NoncePoolError {
    #[error("Background Task stopped")]
    BackgroundClosed,

    #[error("No Nonce returned from API")]
    NoNonce,

    #[error("Hyper Error")]
    Hyper(#[from] hyper::Error),

    #[error("HTTP Error")]
    HTTP(#[from] http::Error),
}

impl NoncePool {
    fn new(client: Client<HTTPSConnector>, url: String) -> Self {
        let (sender, mut receiver) =
            mpsc::channel::<oneshot::Sender<Result<Header, NoncePoolError>>>(64);

        let replay_nonce_header = HeaderName::from_static(REPLAY_NONCE_HEADER);

        tokio::spawn(async move {
            let client = &client;
            let url = &url;
            let replay_nonce_header = &replay_nonce_header;

            let get_nonce = || async move {
                let req = Request::head(url).body(Body::empty())?;
                let mut res = client.request(req).await?;

                res.headers_mut()
                    .remove(replay_nonce_header)
                    .map(Header)
                    .ok_or_else(|| NoncePoolError::NoNonce)
            };

            let mut nonce_cache = None;
            loop {
                // prefetch first nonce from api
                nonce_cache = match nonce_cache.take() {
                    Some(Ok(nonce)) => Some(Ok(nonce)),
                    _ => Some(get_nonce().await),
                };

                // wait till first request for nonce arrives
                let mut sender = match receiver.recv().await {
                    None => break,
                    Some(sender) => sender,
                };

                // if there is no nonce at this stage there was an error while accessing the api
                // so sender gets dropped which will produce an error for the requester
                let nonce = match nonce_cache.take() {
                    None => continue,
                    Some(nonce) => nonce,
                };

                // if we cant send back nonce we keep it arround for the next one
                if let Err(nonce) = sender.send(nonce) {
                    nonce_cache = Some(nonce);
                }
            }
        });

        Self { sender }
    }

    async fn get_nonce(&self) -> Result<Header, NoncePoolError> {
        let (sender, receiver) = oneshot::channel();

        self.sender
            .send(sender)
            .await
            .map_err(|_| NoncePoolError::BackgroundClosed)?;

        receiver
            .await
            .map_err(|_| NoncePoolError::BackgroundClosed)?
    }
}
