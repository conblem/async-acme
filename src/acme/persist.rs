use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::Mutex;

#[derive(Hash, PartialEq, Eq, Copy, Clone, Debug)]
pub enum DataType {
    PrivateKey,
}

// maybe must be send and sync
type BoxFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

pub trait Persist: Debug {
    type Error: Error + Send + 'static;

    fn get<'a, 'b: 'a>(
        &'a self,
        data_type: DataType,
        key: &'b str,
    ) -> BoxFuture<'a, Option<Vec<u8>>, Self::Error>;

    fn put<'a, 'b: 'a>(
        &'a self,
        data_type: DataType,
        key: &'b str,
        value: Vec<u8>,
    ) -> BoxFuture<'a, (), Self::Error>;
}

type Data = HashMap<DataHolder<'static>, Vec<u8>>;

#[derive(Debug)]
pub struct MemoryPersist {
    inner: Mutex<Data>,
}

impl MemoryPersist {
    pub fn new() -> Self {
        MemoryPersist {
            inner: Default::default(),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum DataHolder<'a> {
    PrivateKey(Cow<'a, str>),
}

impl<'a> DataHolder<'a> {
    fn convert<T: Into<Cow<'a, str>>>(data_type: DataType, key: T) -> DataHolder<'a> {
        match data_type {
            DataType::PrivateKey => DataHolder::PrivateKey(key.into()),
        }
    }
}

impl Persist for MemoryPersist {
    type Error = Infallible;

    fn get<'a, 'b: 'a>(
        &'a self,
        data_type: DataType,
        key: &'b str,
    ) -> BoxFuture<'a, Option<Vec<u8>>, Self::Error> {
        let holder = DataHolder::convert(data_type, key);

        Box::pin(async move {
            let lock = self.inner.lock().await;

            Ok(lock.get(&holder).map(ToOwned::to_owned))
        })
    }

    fn put<'a, 'b: 'a>(
        &'a self,
        data_type: DataType,
        key: &'b str,
        value: Vec<u8>,
    ) -> BoxFuture<'a, (), Self::Error> {
        Box::pin(async move {
            let holder = DataHolder::convert(data_type, key.to_string());

            let mut lock = self.inner.lock().await;

            lock.insert(holder, value);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unwrap_infallible::UnwrapInfallible;

    #[tokio::test]
    async fn memory_persist() {
        let persist = MemoryPersist::new();
        let expected = [0, 0, 0, 0];

        persist
            .put(DataType::PrivateKey, "key", expected.to_vec())
            .await
            .unwrap_infallible();
        let actual = persist
            .get(DataType::PrivateKey, "key")
            .await
            .unwrap_infallible();

        assert_eq!(Some(expected.to_vec()), actual);

        let actual = persist
            .get(DataType::PrivateKey, "empty")
            .await
            .unwrap_infallible();
        assert_eq!(None, actual);
    }
}
