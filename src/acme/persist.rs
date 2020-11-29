use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};

pub(super) trait Persist {
    type Error: Error + Send + Sync + 'static;

    fn get<'a>(
        &'a self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::Error>> + 'a>>;
    fn put<'a>(
        &'a self,
        key: &str,
        value: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), Self::Error>> + 'a>>;
}

type Data = HashMap<String, Vec<u8>>;
type PersistError<'a> = PoisonError<MutexGuard<'a, Data>>;

pub(super) struct MemoryPersist {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryPersist {
    fn new() -> Self {
        MemoryPersist {
            inner: Default::default(),
        }
    }
}

impl MemoryPersist {
    fn get<'a>(
        &'a self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, PersistError<'a>>> + 'a>> {
        let data = self.inner.lock().map(|inner| match inner.get(key) {
            Some(entry) => entry.to_owned(),
            None => vec![],
        });

        Box::pin(async move { data })
    }

    fn put<'a>(
        &'a self,
        key: &str,
        value: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), PersistError<'a>>> + 'a>> {
        let key = key.to_owned();
        let value = value.to_owned();

        Box::pin(async move {
            let mut lock = self.inner.lock()?;
            lock.insert(key, value);
            Ok(())
        })
    }
}
