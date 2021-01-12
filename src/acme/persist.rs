use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};

// maybe must be send and sync
type BoxFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

pub(super) trait Persist {
    type Error: Error + Send + 'static;

    fn get<'a>(&'a self, key: &str) -> BoxFuture<'a, Vec<u8>, Self::Error>;

    fn put<'a>(&'a self, key: &str, value: &[u8]) -> BoxFuture<'a, (), Self::Error>;
}

type Data = HashMap<String, Vec<u8>>;
type PersistError<'a> = PoisonError<MutexGuard<'a, Data>>;

pub(super) struct MemoryPersist {
    inner: Mutex<Data>,
}

impl MemoryPersist {
    fn new() -> Self {
        MemoryPersist {
            inner: Default::default(),
        }
    }
}

impl MemoryPersist {
    fn get<'a, 'b: 'a>(&'a self, key: &'b str) -> BoxFuture<'a, Vec<u8>, PersistError<'a>> {
        Box::pin(async move {
            let data = match self.inner.lock()?.get(key) {
                Some(entry) => entry.to_owned(),
                None => vec![],
            };
            Ok(data)
        })
    }

    fn put<'a, 'b: 'a, 'c: 'a>(
        &'a self,
        key: &'b str,
        value: &'c [u8],
    ) -> BoxFuture<'a, (), PersistError<'a>> {
        Box::pin(async move {
            let key = key.to_owned();
            let value = value.to_owned();

            self.inner.lock()?.insert(key, value);
            Ok(())
        })
    }
}
