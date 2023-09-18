use p256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint,
    EncodedPoint,
    ProjectivePoint,
};
use primeorder::elliptic_curve::group::cofactor::CofactorGroup;
use sha2::{Digest, Sha256};

use crate::error::{Result, VrfError};

/// Function to encode a hash, derived from the public key and a given data, to a point in the curve as stated in the
/// [RFC9381](https://datatracker.ietf.org/doc/rfc9381/) (ECVRF_encode_to_curve_try_and_increment, section 5.4.1.1).
///
/// `ECVRF_encode_to_curve_try_and_increment` implements `ECVRF_encode_to_curve` in a simple and generic way that works
/// for any elliptic curve.
///
/// To use this algorithm, `hLen` MUST be at least `fLen`, where:
/// - `hLen` is the output length, in octets, of Hash.
/// - `fLen` is length, in octets, of an element in F encoded as an octet string
///
/// The running time of this algorithm depends on `alpha`. For most ciphersuites, this algorithm is expected to find
/// a valid curve point after approximately two attempts (i.e., when ctr = 1) on average.
/// It is overwhelmingly unlikely that the algorithm does not find a solution (the probability that the ctr counter
/// reaches 256 is about 2^-256).
///
///  However, because the algorithm's running time depends on alpha_string, this algorithm SHOULD be avoided in
///  applications where it is important that the VRF input alpha remain secret.
///
/// # Arguments
///
/// * `encode_to_curve_salt` - A public salt value, an octet string.
/// * `alpha`                - A slice containing the input data, to be hashed.
///
/// # Returns
///
/// * If successful, an EC point representing the hashed value.
pub fn encode_to_curve_tai(encode_to_curve_salt: &[u8], alpha: &[u8]) -> Result<AffinePoint> {
    // Step 1:  ctr = 0
    let mut ctr_range = 0..255;

    // Step 2:  encode_to_curve_domain_separator_front = 0x01
    const ENCODE_TO_CURVE_DOMAIN_SEPARATOR_FRONT: u8 = 0x01;

    // Step 3:  encode_to_curve_domain_separator_back = 0x00
    const ENCODE_TO_CURVE_DOMAIN_SEPARATOR_BACK: u8 = 0x00;

    // TODO: Remove hardcoded suite string (ECVRF_P256_SHA256_TAI)
    let suite_string: u8 = 0x01;

    // Step 4-5: Loop over ctr checking if hash_string is a valid EC point
    // hash_string = Hash(suite_string ||
    //               encode_to_curve_domain_separator_front ||
    //               encode_to_curve_salt || alpha_string || ctr_string ||
    //               encode_to_curve_domain_separator_back)
    let mut hash_input = [
        &[suite_string],
        &[ENCODE_TO_CURVE_DOMAIN_SEPARATOR_FRONT],
        encode_to_curve_salt,
        alpha,
        &[0x00], // First iteration: CTR=0
        &[ENCODE_TO_CURVE_DOMAIN_SEPARATOR_BACK],
    ]
    .concat();

    let ctr_position = hash_input.len() - 2;
    let point_opt = ctr_range.find_map(|ctr| {
        hash_input[ctr_position] = ctr;
        let hash_string = Sha256::digest(&hash_input);
        try_hash_to_point(&hash_string).ok()
    });

    // No solution found (really unlikely with probability about 2^-256)
    let h_point = point_opt.ok_or(VrfError::EncodeToCurveTai)?;

    // Step 5d: H = cofactor * H (ECVRF_validate_key)
    // TODO: recheck cofactor clearing is the same as multiplying by it (p256 has cofactor 1)
    let h_point = ProjectivePoint::from(h_point).clear_cofactor().to_affine();

    Ok(h_point)
}

// Try to interpret a hash value as a EC point as: string_to_point(0x02 || s)
fn try_hash_to_point(data: &[u8]) -> Result<AffinePoint> {
    let mut v = vec![0x02];
    v.extend(data);

    let encoded_point = EncodedPoint::from_bytes(&v).map_err(|e| VrfError::EncodedPoint(e.to_string()))?;
    let point = Option::from(AffinePoint::from_encoded_point(&encoded_point))
        .ok_or(VrfError::AffinePoint("invalid encoded point".to_string()));

    point
}

/// Test vectors extracted from Appendix B.1 of [RFC9381](https://datatracker.ietf.org/doc/rfc9381/).
#[cfg(test)]
mod test {
    use hex_literal::hex;

    use super::*;
    /// Test vector for `P256-SHA256-TAI` ciphersuite.
    /// Source: Example 10 [RFC9381](https://datatracker.ietf.org/doc/rfc9381/) (section B.1).
    /// ASCII: "sample", (ctr = 1)
    #[test]
    fn test_encode_to_curve_tai_1() {
        // Public key
        let public_key = hex!("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
        // Data to be hashed with TAI (ASCII "sample")
        let data = hex!("73616d706c65");

        let point = encode_to_curve_tai(&public_key, &data).unwrap();

        let expected_point = hex!("0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4");
        assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
    }

    /// Test vector for `P256-SHA256-TAI` ciphersuite.
    /// Source: Example 11 [RFC9381](https://datatracker.ietf.org/doc/rfc9381/) (section B.1).
    /// ASCII: "test", (ctr = 3)
    #[test]
    fn test_encode_to_curve_tai_2() {
        // Public key
        let public_key_hex = hex!("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
        // Data to be hashed with TAI (ASCII "test")
        let data = hex!("74657374");

        let point = encode_to_curve_tai(&public_key_hex, &data).unwrap();

        let expected_point = hex!("02173119b4fff5e6f8afed4868a29fe8920f1b54c2cf89cc7b301d0d473de6b974");
        assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
    }

    /// Test vector for `P256-SHA256-TAI` ciphersuite.
    /// Source: Example 12 [RFC9381](https://datatracker.ietf.org/doc/rfc9381/) (section B.1).
    /// ASCII: "Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005", (ctr = 1)
    #[test]
    fn test_encode_to_curve_tai_3() {
        // Public key
        let public_key_hex = hex!("03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d");
        // Data to be hashed with TAI (ASCII "test")
        let data = hex!(
            "4578616d706c65207573696e67204543445341206b65792066726f6d20417070656e646978204c2e342e32206f6620414e53492e58392d36322d32303035"
        );

        let point = encode_to_curve_tai(&public_key_hex, &data).unwrap();

        let expected_point = hex!("0258055c26c4b01d01c00fb57567955f7d39cd6f6e85fd37c58f696cc6b7aa761d");
        assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
    }
}
