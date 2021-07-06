use serde::Serialize;
use std::convert::{TryFrom, TryInto};
use std::error::Error as StdError;
use std::fmt::Debug;
use std::str;

use super::Header;

#[cfg(all(feature = "openssl", not(feature = "rustls")))]
mod openssl;

#[cfg(all(feature = "openssl", not(feature = "rustls")))]
pub use self::openssl::OpenSSLCrypto as CryptoImpl;

#[cfg(feature = "rustls")]
mod ring;

#[cfg(feature = "rustls")]
pub use self::ring::RingCrypto as CryptoImpl;

pub trait Crypto: Debug + Sized + Clone {
    type Signer: Sign<Crypto = Self>;
    type Signature: Serialize + 'static;
    type KeyPair: Serialize
        + Debug
        + TryInto<Vec<u8>, Error = Self::Error>
        + TryFrom<Vec<u8>, Error = Self::Error>
        + 'static;

    type Error: StdError + 'static;

    fn new() -> Result<Self, Self::Error>;

    fn generate_key(&self) -> Result<Self::KeyPair, Self::Error>;
    fn sign<'a, 'b>(
        &'a self,
        key_pair: &'b Self::KeyPair,
        size_hint: usize,
    ) -> Signer<'a, 'b, Self>;

    fn set_kid(&self, keypair: &mut Self::KeyPair, kid: Header);
    fn algorithm(&self, keypair: &Self::KeyPair) -> &'static str;
}

pub trait Sign {
    type Crypto: Crypto;

    fn new(size_hint: usize) -> Self;
    fn update(&mut self, buf: &[u8]);
    fn finish(
        self,
        crypto: &Self::Crypto,
        keypair: &<<Self as Sign>::Crypto as Crypto>::KeyPair,
    ) -> Result<
        <<Self as Sign>::Crypto as Crypto>::Signature,
        <<Self as Sign>::Crypto as Crypto>::Error,
    >;
}

pub struct Signer<'a, 'b, C: Crypto> {
    inner: <C as Crypto>::Signer,
    crypto: &'a C,
    keypair: &'b <C as Crypto>::KeyPair,
}

impl<'a, 'b, C: Crypto> Signer<'a, 'b, C> {
    fn new(crypto: &'a C, keypair: &'b <C as Crypto>::KeyPair, size_hint: usize) -> Self {
        let inner = <C as Crypto>::Signer::new(size_hint);
        Self {
            inner,
            crypto,
            keypair,
        }
    }

    pub fn update<T: AsRef<[u8]>>(&mut self, buf: T) {
        self.inner.update(buf.as_ref())
    }

    pub fn finish(self) -> Result<<C as Crypto>::Signature, <C as Crypto>::Error> {
        let Signer {
            inner,
            keypair,
            crypto,
        } = self;

        inner.finish(crypto, keypair)
    }
}
