use serde::Serialize;
use std::error::Error as StdError;
use std::fmt::Debug;
use std::str;

#[cfg(feature = "native-tls")]
mod openssl;

#[cfg(feature = "native-tls")]
pub use self::openssl::OpenSSLCrypto as CryptoImpl;

#[cfg(feature = "rustls")]
mod ring;

#[cfg(feature = "rustls")]
pub use self::ring::RingCrypto as CryptoImpl;

pub trait Crypto: Debug + Sized {
    type Signature: Serialize;
    type KeyPair: Serialize + AsRef<[u8]>;

    type Error: StdError;

    fn new() -> Result<Self, Self::Error>;

    fn generate_key(&self) -> Result<Self::KeyPair, Self::Error>;
    fn sign<T: AsRef<[u8]>>(
        &self,
        keypair: &Self::KeyPair,
        data: T,
    ) -> Result<Self::Signature, Self::Error>;
    fn set_kid(&self, keypair: &mut Self::KeyPair, kid: String);
    fn algorithm(&self, keypair: &Self::KeyPair) -> &'static str;
}
