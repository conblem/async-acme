use serde::Serialize;
use std::error::Error as StdError;
use std::fmt::Debug;
use std::str;

mod ring;

pub use self::ring::TestCrypto;

pub trait Crypto: Debug {
    type Signature: Serialize;
    type KeyPair: Serialize + AsRef<[u8]>;

    type Error: StdError;

    fn generate_key(&self) -> Result<Self::KeyPair, Self::Error>;
    fn sign<T: AsRef<[u8]>>(
        &self,
        keypair: &Self::KeyPair,
        data: T,
    ) -> Result<Self::Signature, Self::Error>;
    fn set_kid(&self, keypair: &mut Self::KeyPair, kid: String);
    fn algorithm(&self, keypair: &Self::KeyPair) -> &'static str;
}
