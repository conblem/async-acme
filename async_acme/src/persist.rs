use async_trait::async_trait;
use parking_lot::Mutex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Hash, PartialEq, Eq, Copy, Clone, Debug)]
pub enum DataType {
    PrivateKey,
}

#[async_trait]
pub trait Persist: Debug + Clone {
    type Error: Error + Send + Sync + 'static;

    async fn get(&self, data_type: DataType, key: &str) -> Result<Option<Vec<u8>>, Self::Error>;
    async fn put(&self, data_type: DataType, key: &str, value: Vec<u8>) -> Result<(), Self::Error>;
}

type Data = HashMap<DataHolder<'static>, Vec<u8>>;

#[derive(Debug, Clone)]
pub struct MemoryPersist {
    inner: Arc<Mutex<Data>>,
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

#[async_trait]
impl Persist for MemoryPersist {
    type Error = Infallible;

    async fn get(&self, data_type: DataType, key: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        let holder = DataHolder::convert(data_type, key);
        let lock = self.inner.lock();

        Ok(lock.get(&holder).map(ToOwned::to_owned))
    }

    async fn put(&self, data_type: DataType, key: &str, value: Vec<u8>) -> Result<(), Self::Error> {
        let holder = DataHolder::convert(data_type, key.to_string());

        let mut lock = self.inner.lock();

        lock.insert(holder, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    trait UnwrapInfallible<T> {
        fn unwrap_infallible(self) -> T;
    }

    impl<T> UnwrapInfallible<T> for Result<T, Infallible> {
        fn unwrap_infallible(self) -> T {
            match self {
                Ok(res) => res,
                Err(e) => match e {},
            }
        }
    }

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

        let expected = Some(expected.to_vec());
        assert_eq!(actual, expected);

        let actual = persist
            .get(DataType::PrivateKey, "empty")
            .await
            .unwrap_infallible();
        assert_eq!(actual, None);
    }
}
