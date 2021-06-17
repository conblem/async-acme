use serde::Serialize;
use std::error::Error as StdError;
use std::fmt::Debug;
use std::str;

#[cfg(feature = "open-ssl")]
mod openssl;

#[cfg(feature = "open-ssl")]
pub use self::openssl::OpenSSLCrypto as CryptoImpl;

#[cfg(feature = "rustls")]
mod ring;

#[cfg(feature = "rustls")]
pub use self::ring::RingCrypto as CryptoImpl;

pub trait Crypto: Debug + Sized {
    type Signature: Serialize;
    type KeyPair: Serialize;
    type Signer: Sign<Signature = Self::Signature, Error = Self::Error>;

    type Error: StdError;

    fn new() -> Result<Self, Self::Error>;

    fn generate_key(&self) -> Result<Self::KeyPair, Self::Error>;
    fn sign<T: AsRef<[u8]>>(
        &self,
        keypair: &Self::KeyPair,
    ) -> Result<Self::Signature, Self::Error>;
    fn set_kid(&self, keypair: &mut Self::KeyPair, kid: String);
    fn algorithm(&self, keypair: &Self::KeyPair) -> &'static str;
}

pub trait Sign {
    type Signature: Serialize;

    type Error: StdError;

    fn update(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
    fn finish(self) -> Result<Self::Signature, Self::Error>;
}
