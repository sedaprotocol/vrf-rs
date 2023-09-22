use std::ops::Mul;

use elliptic_curve::{
    generic_array::typenum::Unsigned,
    group::cofactor::CofactorGroup,
    ops::MulByGenerator,
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve,
    CurveArithmetic,
    FieldBytesEncoding,
    ProjectivePoint,
    Scalar,
    ScalarPrimitive,
};
use sha2::{
    digest::{crypto_common::BlockSizeUser, FixedOutput, FixedOutputReset},
    Digest,
};

use crate::error::{Result, VrfError};

trait EcVrf
where
    Self::Curve: CurveArithmetic,
    <Self::Curve as Curve>::FieldBytesSize: ModulusSize,
    <Self::Curve as CurveArithmetic>::AffinePoint: FromEncodedPoint<Self::Curve>,
    <Self::Curve as CurveArithmetic>::ProjectivePoint: ToEncodedPoint<Self::Curve> + CofactorGroup,
{
    type Curve;
    type Hasher: Digest
        + BlockSizeUser
        + FixedOutput<OutputSize = <Self::Curve as Curve>::FieldBytesSize>
        + FixedOutputReset;

    // cipher suite id
    const SUITE_ID: u8;

    // curve cofactor
    const COFACTOR: Scalar<Self::Curve>;
    // ptLen:  length, in octets, of a point on E encoded as an octet string or close to it)
    const PT_LEN: usize;
    // qLen:  length of q, in octets, i.e., the smallest integer such that 2^(8qLen) > q
    const Q_LEN: usize;
    // cLen:  length, in octets, of a challenge value used by the VRF (note that in the typical case, cLen is qLen/2
    const C_LEN: usize;

    fn encode_to_curve_tai(
        &self,
        encode_to_curve_salt: &[u8],
        alpha: &[u8],
    ) -> Result<<Self::Curve as CurveArithmetic>::AffinePoint> {
        // Step 1:  ctr = 0
        let mut ctr_range = 0..255;

        // Step 2-3:  domain separators & cipher suite
        const ENCODE_TO_CURVE_DOMAIN_SEPARATOR_FRONT: u8 = 0x01;
        const ENCODE_TO_CURVE_DOMAIN_SEPARATOR_BACK: u8 = 0x00;

        // Step 4-5: Loop over ctr checking if hash_string is a valid EC point
        // hash_string = Hash(suite_string ||
        //               encode_to_curve_domain_separator_front ||
        //               encode_to_curve_salt || alpha_string || ctr_string ||
        //               encode_to_curve_domain_separator_back)
        let mut hash_input = [
            &[Self::SUITE_ID],
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
            let hash_string = Self::Hasher::digest(&hash_input);
            self.try_hash_to_point(&hash_string).ok()
        });

        // No solution found (really unlikely with probability about 2^-256)
        let h_point = point_opt.ok_or(VrfError::EncodeToCurveTai)?;

        // Step 5d: H = cofactor * H (ECVRF_validate_key)
        // TODO(Mario): recheck cofactor clearing is the same as multiplying by it (p256 has cofactor 1)
        // let h_point = ProjectivePoint::<C>::from(h_point).clear_cofactor().to_affine();

        Ok(h_point)
    }

    // ECVRF_challenge_generation
    fn challenge_generation(&self, points: &[&[u8]]) -> Result<Vec<u8>> {
        // Step 1: challenge_generation_domain_separator_front = 0x02
        const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT: u8 = 0x02;

        // point_bytes = [P1||P2||...||Pn]
        let point_bytes: Result<Vec<u8>> = points.iter().try_fold(
            // Step 2: Initialize str = suite_string || challenge_generation_domain_separator_front
            vec![Self::SUITE_ID, CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT],
            // Step 3: For PJ in [P1, P2, P3, P4, P5]: str = str || point_to_string(PJ)
                |mut acc, &point| {
                    acc.extend(point.to_vec());

                    Ok(acc)
                },
            );
        let to_be_hashed = point_bytes?;

        // Step 4: challenge_generation_domain_separator_back = 0x00
        const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK: u8 = 0x00;

        // Step 5-6: c_String = Hash(str) = Hash (str || challenge_generation_domain_separator_back)
        // Hash (suite_string || challenge_generation_domain_separator_front || point_bytes ||
        // challenge_generation_domain_separator_back)
        let mut c_string =
            Self::Hasher::digest([&to_be_hashed[..], &[CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK]].concat()).to_vec();

        // Step 7: truncated_c_string = c_string[0]...c_string[cLen-1]
        c_string.truncate(Self::C_LEN);

        // Step 8: c = string_to_int(truncated_c_string)
        // Note: not needed because `prove` and `verify` functions need bytes and scalar values

        Ok(c_string)
    }

    // ECVRF_decode_proof(pi_string)
    fn decode_proof(&self, pi: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        // Expected size of proof: len(pi) = len(gamma) + len(c) + len(s)
        // len(s) = 2 * len(c), so len(pi) = len(gamma) + 3 * len(c)
        let gamma_oct = Self::PT_LEN + 1;
        if pi.len() != gamma_oct + Self::C_LEN * 3 {
            return Err(VrfError::InvalidPiLength);
        }

        // Gamma point
        let gamma = pi[0..gamma_oct].to_vec();

        // C scalar (needs to be padded with leading zeroes)
        let mut c_scalar: Vec<u8> = vec![0; <Self::Curve as Curve>::FieldBytesSize::USIZE - Self::C_LEN];
        c_scalar.extend_from_slice(&pi[gamma_oct..gamma_oct + Self::C_LEN]);

        // S scalar
        let s_scalar = pi[gamma_oct + Self::C_LEN..].to_vec();

        Ok((gamma, c_scalar, s_scalar))
    }

    fn try_hash_to_point(&self, data: &[u8]) -> Result<<Self::Curve as CurveArithmetic>::AffinePoint> {
        let mut point_bytes = vec![0x02];
        point_bytes.extend(data);

        self.point_from_bytes(&point_bytes)
    }

    fn point_from_bytes(&self, data: &[u8]) -> Result<<Self::Curve as CurveArithmetic>::AffinePoint> {
        let encoded_point: EncodedPoint<Self::Curve> =
            EncodedPoint::<Self::Curve>::from_bytes(data).map_err(|e| VrfError::EncodedPoint(e.to_string()))?;

        Option::from(<Self::Curve as CurveArithmetic>::AffinePoint::from_encoded_point(
            &encoded_point,
        ))
            .ok_or(VrfError::AffinePoint("invalid encoded point".to_string()))
    }

    fn scalar_from_bytes(&self, data: &[u8]) -> Result<Scalar<Self::Curve>> {
        let primitive = ScalarPrimitive::<Self::Curve>::from_slice(data)?;

        Ok(primitive.into())
    }

    fn prove(&self, secret_key: &[u8], alpha: &[u8]) -> Result<Vec<u8>> {
        // Step 1: derive public key from secret key as `Y = x * B`
        //TODO: validate secret key length?
        let secret_key_scalar = self.scalar_from_bytes(secret_key)?;
        let public_key_point = <Self::Curve as CurveArithmetic>::ProjectivePoint::mul_by_generator(&secret_key_scalar);

        let public_key_bytes: Vec<u8> = public_key_point.to_encoded_point(true).to_bytes().to_vec();

        // Step 2: Encode to curve (using TAI)
        let h_point = ProjectivePoint::<Self::Curve>::from(self.encode_to_curve_tai(&public_key_bytes, alpha)?);
        let h_point_bytes = h_point.to_encoded_point(true).to_bytes().to_vec();

        // Step 3: point to string (or bytes)
        let h_bytes = h_point.to_encoded_point(true).to_bytes().to_vec();

        // Step 4: Gamma = x * H
        let gamma_point = h_point.mul(secret_key_scalar);
        let gamma_point_bytes = gamma_point.to_encoded_point(true).to_bytes().to_vec();

        // Step 5: nonce (k generation)
        let k_scalar = self.generate_nonce(secret_key, &Self::Hasher::digest(h_bytes))?;

        // Step 6: c = ECVRF_challenge_generation (Y, H, Gamma, U, V)
        // U = k*B = k&Generator
        let u_point = <Self::Curve as CurveArithmetic>::ProjectivePoint::mul_by_generator(&k_scalar);
        let u_point_bytes = u_point.to_encoded_point(true).to_bytes().to_vec();
        // V = k*H
        let v_point = h_point * k_scalar;
        let v_point_bytes = v_point.to_encoded_point(true).to_bytes().to_vec();
        // Challenge generation (returns hash output truncated by `cLen`)
        let c_scalar_bytes = self.challenge_generation(&[
            &public_key_bytes,
            &h_point_bytes,
            &gamma_point_bytes,
            &u_point_bytes,
            &v_point_bytes,
        ])?;
        let mut c_padded_bytes: Vec<u8> = vec![0; <Self::Curve as Curve>::FieldBytesSize::USIZE - Self::C_LEN];
        c_padded_bytes.extend_from_slice(&c_scalar_bytes);
        let c_scalar = self.scalar_from_bytes(&c_padded_bytes)?;

        // Step 7: s = (k + c*x) mod q
        let s_scalar = k_scalar + c_scalar * secret_key_scalar;
        let s_scalar_bytes = Into::<ScalarPrimitive<Self::Curve>>::into(s_scalar).to_bytes();

        // Step 8: encode (gamma, c, s)
        let proof = [&gamma_point_bytes[..], &c_scalar_bytes, &s_scalar_bytes].concat();

        Ok(proof)
    }

    fn verify(&self, public_key: &[u8], pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>> {
        // Step 1-2: Y = string_to_point(PK_string)
        let public_key_point =
            <Self::Curve as CurveArithmetic>::ProjectivePoint::from(self.point_from_bytes(public_key)?);

        // Step 3: If validate_key, run ECVRF_validate_key(Y) (Section 5.4.5); if it outputs "INVALID", output "INVALID"
        // TODO: Check step 3 again
        if public_key_point.is_small_order().into() {
            return Err(VrfError::InvalidPoint(
                "provided public key bytes is not a valid EC point".to_string(),
            ));
        }

        // Step 4-6: D = ECVRF_decode_proof(pi_string)
        let (gamma_point_bytes, c_scalar_bytes, s_scalar_bytes) = self.decode_proof(pi)?;
        let gamma_point =
            <Self::Curve as CurveArithmetic>::ProjectivePoint::from(self.point_from_bytes(&gamma_point_bytes)?);
        let c_scalar = self.scalar_from_bytes(&c_scalar_bytes)?;
        let s_scalar = self.scalar_from_bytes(&s_scalar_bytes)?;

        // Step 7: H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
        let h_point = ProjectivePoint::<Self::Curve>::from(self.encode_to_curve_tai(public_key, alpha)?);
        let h_point_bytes = h_point.to_encoded_point(true).to_bytes().to_vec();

        // Step 8: U = s*B - c*Y
        let u_point = <Self::Curve as CurveArithmetic>::ProjectivePoint::mul_by_generator(&s_scalar)
            - public_key_point * c_scalar;
        let u_point_bytes = u_point.to_encoded_point(true).to_bytes().to_vec();

        // Step 9: V = s*H - c*Gamma
        let v_point = h_point * s_scalar - gamma_point * c_scalar;
        let v_point_bytes = v_point.to_encoded_point(true).to_bytes().to_vec();

        // Step 10: c' = ECVRF_challenge_generation(Y, H, Gamma, U, V)
        let derived_c_bytes = self.challenge_generation(&[
            public_key,
            &h_point_bytes,
            &gamma_point_bytes,
            &u_point_bytes,
            &v_point_bytes,
        ])?;
        let mut padded_derived_c_bytes: Vec<u8> = vec![0; <Self::Curve as Curve>::FieldBytesSize::USIZE - Self::C_LEN];
        padded_derived_c_bytes.extend_from_slice(&derived_c_bytes);

        // Step 11: Check if c and c' are equal
        if padded_derived_c_bytes != c_scalar_bytes {
            return Err(VrfError::InvalidProof);
        }

        // If valid VRF proof, ECVRF_proof_to_hash(pi_string)
        let beta = self.gamma_to_hash(&gamma_point)?;

        Ok(beta)
    }

    fn gamma_to_hash(&self, gamma: &<Self::Curve as CurveArithmetic>::ProjectivePoint) -> Result<Vec<u8>> {
        // Step 4: proof_to_hash_domain_separator_front = 0x03
        const PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT: u8 = 0x03;

        // Step 5: proof_to_hash_domain_separator_back = 0x00
        const PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK: u8 = 0x00;

        // Step 6: Compute beta
        // beta_string = Hash(suite_string || proof_to_hash_domain_separator_front ||
        //                    point_to_string(cofactor * Gamma) || proof_to_hash_domain_separator_back)
        let point: ProjectivePoint<Self::Curve> = gamma.mul(Self::COFACTOR);
        let point_bytes = point.to_encoded_point(true).to_bytes().to_vec();

        let beta = Self::Hasher::digest(
            [
                &[Self::SUITE_ID],
                &[PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT],
                &point_bytes[..],
                &[PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK],
            ]
            .concat(),
        )
        .to_vec();

        Ok(beta)
    }

    // ECVRF_nonce_generation_RFC6979(SK, h_string)
    fn generate_nonce(&self, secret_key: &[u8], digest_msg: &[u8]) -> Result<Scalar<Self::Curve>> {
        let k = rfc6979::generate_k::<Self::Hasher, <Self::Curve as Curve>::FieldBytesSize>(
            secret_key.into(),
            &FieldBytesEncoding::encode_field_bytes(&<Self::Curve as Curve>::ORDER),
            digest_msg.into(),
            &[],
        );

        self.scalar_from_bytes(&k)
    }
}

struct P256Sha256;

impl EcVrf for P256Sha256 {
    type Curve = p256::NistP256;
    type Hasher = sha2::Sha256;

    const COFACTOR: Scalar<Self::Curve> = <Self::Curve as CurveArithmetic>::Scalar::ONE;
    const C_LEN: usize = Self::Q_LEN / 2;
    const PT_LEN: usize = <Self::Curve as Curve>::Uint::MAX.bits() / 8;
    const Q_LEN: usize = <Self::Curve as Curve>::ORDER.bits() / 8;
    const SUITE_ID: u8 = 0x01;
}

struct Secp256k1Sha256;

impl EcVrf for Secp256k1Sha256 {
    type Curve = k256::Secp256k1;
    type Hasher = sha2::Sha256;

    const COFACTOR: Scalar<Self::Curve> = <Self::Curve as CurveArithmetic>::Scalar::ONE;
    const C_LEN: usize = Self::Q_LEN / 2;
    const PT_LEN: usize = <Self::Curve as Curve>::Uint::MAX.bits() / 8;
    const Q_LEN: usize = <Self::Curve as Curve>::ORDER.bits() / 8;
    const SUITE_ID: u8 = 0xFE;
}

#[cfg(test)]
mod test {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn p256_sha256_tai_encode_to_curve_1() {
        let vrf = P256Sha256;
        let public_key = hex!("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
        let alpha = b"sample";

        let point = vrf.encode_to_curve_tai(&public_key, alpha).unwrap();

        let expected_point = hex!("0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4");
        assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
    }

    #[test]
    fn secp256k1_sha256_tai_encode_to_curve() {
        let vrf = Secp256k1Sha256;
        let public_key = hex!("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645");
        let alpha = b"sample";

        let point = vrf.encode_to_curve_tai(&public_key, alpha).unwrap();

        let expected_point = hex!("0221ceb1ce22cd34d8b73a619164ed64e917ca31fd454075d02e4bdfa9c5ce0b48");
        assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
    }

    /// Same as `p256_sha256_tai_encode_to_curve_1`
    #[test]
    fn test_decode_proof() {
        let vrf = P256Sha256;
        let pi = hex!(
            "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f"
        );
        let (gamma, c, s) = vrf.decode_proof(&pi).unwrap();

        // Expected values
        let expected_gamma = hex!("035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4");
        let expected_c = hex!("00000000000000000000000000000000a53f0a46f018bc2c56e58d383f2305e0");
        let expected_s = hex!("975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f");

        assert_eq!(gamma, expected_gamma);
        assert_eq!(c, expected_c);
        assert_eq!(s, expected_s);
    }

    /// Source: RFC 6979 (A.2.5.  ECDSA, 256 Bits (Prime Field))
    #[test]
    fn test_nonce_generation() {
        let vrf = P256Sha256;
        let secret_key = hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let alpha = b"sample";
        let k = vrf.generate_nonce(&secret_key, &sha2::Sha256::digest(alpha)).unwrap();

        let expected_k = hex!("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
        assert_eq!(k.to_bytes().as_slice(), &expected_k);
    }

    /// Source: Example 10
    #[test]
    fn test_prove_p256_sha256_tai_1() {
        let vrf = P256Sha256;
        let secret_key = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let alpha = b"sample";
        let pi = vrf.prove(&secret_key, alpha).unwrap();

        let expected_pi = hex!(
            "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f"
        ).to_vec();
        assert_eq!(pi, expected_pi);
    }

    /// Source: Example 10
    #[test]
    fn test_verify_p256_sha256_tai_1() {
        let vrf = P256Sha256;
        let public_key = hex!("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
        let alpha = b"sample";
        let pi = hex!(
            "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f"
        );
        let beta = vrf.verify(&public_key, &pi, alpha).unwrap();

        let expected_beta = hex!("a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e");
        assert_eq!(beta, expected_beta);
    }

    // #[test]
    // fn playground() {
    //     const C_LEN: usize = Q_LEN / 2;
    //     const PT_LEN: usize = <NistP256 as Curve>::Uint::MAX.bits() / 8;
    //     const Q_LEN: usize = <NistP256 as Curve>::ORDER.bits() / 8;
    //     println!("====> pt_len {}, q_len {}, c_len: {}", PT_LEN, Q_LEN, C_LEN);
    // }
}
