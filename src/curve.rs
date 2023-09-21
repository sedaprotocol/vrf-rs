use std::ops::Mul;

use elliptic_curve::{
    generic_array::typenum::Unsigned,
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
    <Self::Curve as CurveArithmetic>::ProjectivePoint: ToEncodedPoint<Self::Curve>,
{
    type Curve;
    type Hasher: Digest
        + BlockSizeUser
        + FixedOutput<OutputSize = <Self::Curve as Curve>::FieldBytesSize>
        + FixedOutputReset;

    // cipher suite id
    const SUITE_ID: u8;
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
        let suite_string: u8 = Self::SUITE_ID;

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
            let hash_string = Self::Hasher::digest(&hash_input);
            self.try_hash_to_point(&hash_string).ok()
        });

        // No solution found (really unlikely with probability about 2^-256)
        let h_point = point_opt.ok_or(VrfError::EncodeToCurveTai)?;

        // Step 5d: H = cofactor * H (ECVRF_validate_key)
        // TODO: recheck cofactor clearing is the same as multiplying by it (p256 has cofactor 1)
        // let h_point = ProjectivePoint::<C>::from(h_point).clear_cofactor().to_affine();

        Ok(h_point)
    }

    // ECVRF_challenge_generation
    fn challenge_generation(&self, points: &[&[u8]]) -> Result<Vec<u8>> {
        // TODO: change this
        // ECVRF_P256_SHA256_TAI
        let suite_string: u8 = 0x01;

        const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT: u8 = 0x02;
        const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK: u8 = 0x00;

        // point_bytes = [P1||P2||...||Pn]
        // 1. challenge_generation_domain_separator_front = 0x02
        let point_bytes: Result<Vec<u8>> = points
            .iter()
            // 2. Initialize str = suite_string || challenge_generation_domain_separator_front
            // 3. For PJ in [P1, P2, P3, P4, P5]: str = str || point_to_string(PJ)
            .try_fold(
                vec![suite_string, CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT],
                |mut acc, &point| {
                    // The point_to_string function converts a point on E to an octet string with point compression on.
                    // This implies that ptLen = fLen + 1 = 33.
                    acc.extend(point.to_vec());

                    Ok(acc)
                },
            );
        let to_be_hashed = point_bytes?;
        // 4. challenge_generation_domain_separator_back = 0x00
        // 5. str = str || challenge_generation_domain_separator_back
        // 6. c_string = Hash(str)

        // H(suite_string || challenge_generation_domain_separator_front || point_bytes ||
        // challenge_generation_domain_separator_back)
        let mut c_string =
            Self::Hasher::digest([&to_be_hashed[..], &[CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK]].concat()).to_vec();

        // 7. truncated_c_string = c_string[0]...c_string[cLen-1]
        c_string.truncate(Self::C_LEN);

        // TODO(Mario): Check if we need to conver to integer
        // 8. c = string_to_int(truncated_c_string)
        // let c = BigNum::from_slice(c_string.as_slice())?;

        Ok(c_string)
    }

    // ECVRF_decode_proof(pi_string)
    fn decode_proof(
        &self,
        pi: &[u8],
    ) -> Result<(
        <Self::Curve as CurveArithmetic>::AffinePoint,
        <Self::Curve as CurveArithmetic>::Scalar,
        <Self::Curve as CurveArithmetic>::Scalar,
    )> {
        // Expected size of proof: len(pi) = len(gamma) + len(c) + len(s)
        // len(s) = 2 * len(c), so len(pi) = len(gamma) + 3 * len(c)
        let gamma_oct = Self::PT_LEN + 1;
        if pi.len() != gamma_oct + Self::C_LEN * 3 {
            return Err(VrfError::InvalidPiLength);
        }

        // Gamma point
        let gamma = self.point_from_bytes(&pi[0..gamma_oct])?;
        // C scalar (needs to be padded with leading zeroes)
        let mut c_bytes: Vec<u8> = vec![0; <Self::Curve as Curve>::FieldBytesSize::USIZE - Self::C_LEN];
        c_bytes.extend_from_slice(&pi[gamma_oct..gamma_oct + Self::C_LEN]);
        let c_scalar = self.scalar_from_bytes(&c_bytes)?;
        // S scalar
        let s_scalar = self.scalar_from_bytes(&pi[gamma_oct + Self::C_LEN..])?;

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
}

struct P256Sha256;

impl EcVrf for P256Sha256 {
    type Curve = p256::NistP256;
    type Hasher = sha2::Sha256;

    const C_LEN: usize = Self::Q_LEN / 2;
    const PT_LEN: usize = <Self::Curve as Curve>::Uint::MAX.bits() / 8;
    const Q_LEN: usize = <Self::Curve as Curve>::ORDER.bits() / 8;
    const SUITE_ID: u8 = 0x01;
}

struct Secp256k1Sha256;

impl EcVrf for Secp256k1Sha256 {
    type Curve = k256::Secp256k1;
    type Hasher = sha2::Sha256;

    const C_LEN: usize = Self::Q_LEN / 2;
    const PT_LEN: usize = <Self::Curve as Curve>::Uint::MAX.bits() / 8;
    const Q_LEN: usize = <Self::Curve as Curve>::ORDER.bits() / 8;
    const SUITE_ID: u8 = 0xFE;
}

#[cfg(test)]
mod test {
    use elliptic_curve::sec1::ToEncodedPoint;
    use hex_literal::hex;

    use super::*;

    #[test]
    fn p256_sha256_tai_encode_to_curve_1() {
        let my_curve = P256Sha256;
        let public_key = hex!("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
        let alpha = hex!("73616d706c65");

        let point = my_curve.encode_to_curve_tai(&public_key, &alpha).unwrap();

        let expected_point = hex!("0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4");
        assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
    }

    #[test]
    fn secp256k1_sha256_tai_encode_to_curve() {
        let my_curve = Secp256k1Sha256;
        let public_key = hex!("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645");
        let alpha = hex!("73616d706c65");

        let point = my_curve.encode_to_curve_tai(&public_key, &alpha).unwrap();

        let expected_point = hex!("0221ceb1ce22cd34d8b73a619164ed64e917ca31fd454075d02e4bdfa9c5ce0b48");
        assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
    }

    /// Same as `p256_sha256_tai_encode_to_curve_1`
    #[test]
    fn test_decode_proof() {
        let my_curve = P256Sha256;

        let pi = hex!(
            "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f"
        );
        let (gamma_point, c_scalar, s_scalar) = my_curve.decode_proof(&pi).unwrap();

        // Expected values
        let expected_gamma = p256::AffinePoint::try_from(
            p256::EncodedPoint::from_bytes(hex!(
                "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4"
            ))
            .unwrap(),
        )
        .unwrap();
        let expected_c = p256::Scalar::from(
            ScalarPrimitive::from_slice(&hex!(
                "00000000000000000000000000000000a53f0a46f018bc2c56e58d383f2305e0"
            ))
            .unwrap(),
        );
        let expected_s = p256::Scalar::from(
            ScalarPrimitive::from_slice(&hex!(
                "975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f"
            ))
            .unwrap(),
        );

        assert!(expected_gamma.eq(&gamma_point));
        assert!(c_scalar.eq(&expected_c));
        assert!(s_scalar.eq(&expected_s));
    }

    // #[test]
    // fn playground() {
    //     const C_LEN: usize = Q_LEN / 2;
    //     const PT_LEN: usize = <NistP256 as Curve>::Uint::MAX.bits() / 8;
    //     const Q_LEN: usize = <NistP256 as Curve>::ORDER.bits() / 8;
    //     println!("====> pt_len {}, q_len {}, c_len: {}", PT_LEN, Q_LEN, C_LEN);
    // }
}
