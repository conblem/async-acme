use hyper;
use hyper::client::connect::Connect;
use hyper::header::HeaderName;
use hyper::http;
use hyper::{Body, Client, Request};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::{debug_span, info_span, Instrument, Span};

use super::{Header, HttpsConnector};

const REPLAY_NONCE_HEADER: &str = "replay-nonce";

#[derive(Debug)]
pub(crate) struct NoncePool {
    sender: mpsc::Sender<oneshot::Sender<Result<Header, NoncePoolError>>>,
    span: Span,
}

#[derive(Error, Debug)]
pub(crate) enum NoncePoolError {
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
    pub(crate) fn new<C: Connect + Clone + Send + Sync + 'static>(
        client: Client<C>,
        url: String,
    ) -> Self {
        let span = info_span!("NoncePool");
        let guard = span.enter();

        let (sender, mut receiver) =
            mpsc::channel::<oneshot::Sender<Result<Header, NoncePoolError>>>(64);

        let replay_nonce_header = HeaderName::from_static(REPLAY_NONCE_HEADER);

        tokio::spawn(
            async move {
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
                    let sender = match receiver.recv().await {
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
            }
            .instrument(span.clone()),
        );

        drop(guard);
        Self { sender, span }
    }

    pub(crate) async fn get_nonce(&self) -> Result<Header, NoncePoolError> {
        let span = debug_span!(parent: &self.span, "Get Nonce");

        async move {
            let (sender, receiver) = oneshot::channel();

            self.sender
                .send(sender)
                .await
                .map_err(|_| NoncePoolError::BackgroundClosed)?;

            receiver
                .await
                .map_err(|_| NoncePoolError::BackgroundClosed)?
        }
        .instrument(span)
        .await
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use std::error::Error;

    async fn create_mock_server(response: ResponseTemplate) -> MockServer {
        let mock_server = MockServer::start().await;

        Mock::given(method("HEAD"))
            .and(path("/new_nonce"))
            .respond_with(response)
            .mount(&mock_server)
            .await;

        mock_server
    }

    fn create_pool(url: String) -> NoncePool {
        NoncePool::new(Client::new(), url)
    }

    #[tokio::test]
    async fn test() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        let expected = "nonce-12345";
        let response = ResponseTemplate::new(200).append_header(REPLAY_NONCE_HEADER, expected);
        let mock_server = create_mock_server(response).await;

        let pool = create_pool(format!("{}/new_nonce", &mock_server.uri()));

        let actual = pool.get_nonce().await?;
        assert_eq!(expected, actual.to_str()?);

        Ok(())
    }
}
