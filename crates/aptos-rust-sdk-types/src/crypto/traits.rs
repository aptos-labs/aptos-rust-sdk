pub trait PrivateKey<P: PublicKey<S>, S: Signature> {
    fn sign<T: AsRef<[u8]>>(&self, bytes: T) -> S;

    fn public_key(&self) -> P;
}

pub trait PublicKey<S: Signature> {
    fn verify<T: AsRef<[u8]>>(&self, payload: T, signature: &S) -> anyhow::Result<()>;
}

pub trait Signature {}
