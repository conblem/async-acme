use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

mod acme;

fn _generate_private() {
    let random = SystemRandom::new();
    let key_pair = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
    Ed25519KeyPair::from_pkcs8(key_pair.as_ref());
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
