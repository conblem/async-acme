use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

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

#[derive(Debug)]
pub struct PoisonError;

impl Display for PoisonError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "poisoned lock: another task failed inside")
    }
}

impl Error for PoisonError {}

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
    type Error = PoisonError;

    fn get<'a, 'b: 'a>(
        &'a self,
        data_type: DataType,
        key: &'b str,
    ) -> BoxFuture<'a, Option<Vec<u8>>, Self::Error> {
        let holder = DataHolder::convert(data_type, key);

        Box::pin(async move {
            let lock = match self.inner.lock() {
                Err(_) => Err(PoisonError)?,
                Ok(lock) => lock,
            };

            Ok(lock.get(&holder).map(ToOwned::to_owned))
        })
    }

    fn put<'a, 'b: 'a>(
        &'a self,
        data_type: DataType,
        key: &'b str,
        value: Vec<u8>
    ) -> BoxFuture<'a, (), Self::Error> {
        Box::pin(async move {
            let holder = DataHolder::convert(data_type, key.to_string());

            let mut lock = match self.inner.lock() {
                Err(_) => Err(PoisonError)?,
                Ok(lock) => lock,
            };

            lock.insert(holder, value);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_add() {
        assert_eq!(add(2, 3), 5);
    }
}