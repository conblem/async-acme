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

pub trait Crypto: Debug + Sized
{
    type Signer: Sign<Crypto = Self>;
    type Signature: Serialize + 'static;
    type KeyPair: Serialize + 'static;

    type Error: StdError + 'static;

    fn new() -> Result<Self, Self::Error>;

    fn generate_key(&self) -> Result<Self::KeyPair, Self::Error>;
    fn sign<'a, H: Into<Option<usize>>>(
        &self,
        size_hint: H,
    ) -> Self::Signer;

    fn set_kid(&self, keypair: &mut Self::KeyPair, kid: String);
    fn algorithm(&self, keypair: &Self::KeyPair) -> &'static str;
}

pub trait Sign {
    type Crypto: Crypto;

    fn update<T: AsRef<[u8]>>(&mut self, buf: T);
    fn finish(
        self,
        keypair: &<<Self as Sign>::Crypto as Crypto>::KeyPair,
    ) -> Result<
        <<Self as Sign>::Crypto as Crypto>::Signature,
        <<Self as Sign>::Crypto as Crypto>::Error,
    >;
}
