mod challenge;
pub mod ecvrf;
mod encode_to_curve;
pub mod error;
mod nonce;
mod utils;

pub struct VrfStruct<Curve, Hasher> {
    // Elliptic Curve
    pub curve:    Curve,
    // Hash Function
    pub hasher:   Hasher,
    /// ECVRF suite string as specific by RFC9381
    pub suite_id: u8,
}

impl<C: Default, D: Default> VrfStruct<C, D> {
    pub fn new(suite_id: u8) -> Self {
        Self {
            curve: C::default(),
            hasher: D::default(),
            suite_id,
        }
    }
}

pub type P256k1Sha256 = VrfStruct<p256::NistP256, sha2::Sha256>;
impl Default for P256k1Sha256 {
    fn default() -> Self {
        Self {
            curve:    Default::default(),
            hasher:   Default::default(),
            suite_id: 0x01,
        }
    }
}

pub type Secp256k1Sha256 = VrfStruct<k256::Secp256k1, sha2::Sha256>;
impl Default for Secp256k1Sha256 {
    fn default() -> Self {
        Self {
            curve:    Default::default(),
            hasher:   Default::default(),
            suite_id: 0xFE,
        }
    }
}

#[cfg(test)]
#[path = ""]
pub mod test {
    mod ecvrf_test;
}
