pub mod dto;
pub mod request;
pub mod server;

mod sealed {
    pub trait Sealed {}

    impl Sealed for super::PrivateImpl {}
}

pub trait Private: sealed::Sealed + Send + Sync {}

struct PrivateImpl;
impl Private for PrivateImpl {}
