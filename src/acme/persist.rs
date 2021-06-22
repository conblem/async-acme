use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

// maybe must be send and sync
type BoxFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

pub trait Persist: Debug {
    type Error: Error + Send + 'static;

    fn get<'a, 'b: 'a>(&'a self, key: &'b str) -> BoxFuture<'a, Option<Vec<u8>>, Self::Error>;

    fn put<'a, 'b: 'a, 'c: 'a>(
        &'a self,
        key: &'b str,
        value: &'c [u8],
    ) -> BoxFuture<'a, (), Self::Error>;
}

type Data = HashMap<String, Vec<u8>>;

#[derive(Debug)]
pub struct MemoryPersist {
    inner: Mutex<Data>,
}

#[derive(Debug)]
pub struct PoisonError;

impl Display for PoisonError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "poisoned lock: another task failed inside")
    }
}

impl Error for PoisonError {}

impl MemoryPersist {
    pub fn new() -> Self {
        MemoryPersist {
            inner: Default::default(),
        }
    }
}

impl Persist for MemoryPersist {
    type Error = PoisonError;

    fn get<'a, 'b: 'a>(&'a self, key: &'b str) -> BoxFuture<'a, Option<Vec<u8>>, Self::Error> {
        Box::pin(async move {
            let lock = match self.inner.lock() {
                Err(_) => Err(PoisonError)?,
                Ok(lock) => lock,
            };

            Ok(lock.get(key).map(ToOwned::to_owned))
        })
    }

    fn put<'a, 'b: 'a, 'c: 'a>(
        &'a self,
        key: &'b str,
        value: &'c [u8],
    ) -> BoxFuture<'a, (), Self::Error> {
        Box::pin(async move {
            let key = key.to_owned();
            let value = value.to_owned();

            let mut lock = match self.inner.lock() {
                Err(_) => Err(PoisonError)?,
                Ok(lock) => lock,
            };

            lock.insert(key, value);
            Ok(())
        })
    }
}
