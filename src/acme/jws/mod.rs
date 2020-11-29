use base64::URL_SAFE;
use ring::signature::Signature;
use serde::ser::{
    Error as SerError, SerializeStruct, SerializeStructVariant, SerializeTupleVariant,
};
use serde::{Serialize, Serializer};
use std::borrow::Cow;
use std::convert::AsRef;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;

mod ed25519;

fn base64_serialize<T, S>(input: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    let base = base64::encode_config(input, URL_SAFE);

    serializer.serialize_str(base.as_str())
}
