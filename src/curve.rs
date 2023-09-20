use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize},
    Curve as EllipticCurve,
    CurveArithmetic,
};
use sha2::Digest;

use crate::error::{Result, VrfError};

trait EcVrf
where
    Self::Curve: CurveArithmetic,
    <Self::Curve as EllipticCurve>::FieldBytesSize: ModulusSize,
    <Self::Curve as CurveArithmetic>::AffinePoint: FromEncodedPoint<Self::Curve>,
{
    type Curve;
    type Hasher: Digest;

    const SUITE_ID: u8;
    const ORDER_BITS: usize;

    fn encode_to_curve_tai(
        &self,
        encode_to_curve_salt: &[u8],
        alpha: &[u8],
    ) -> Result<<Self::Curve as elliptic_curve::CurveArithmetic>::AffinePoint> {
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
                |mut acc, point| {
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

        // .map(|hash| hash.to_vec())?;

        // 7. truncated_c_string = c_string[0]...c_string[cLen-1]
        // cLen:  length, in octets, of a challenge value used by the VRF (typically, cLen is qLen/2 or close to it)
        // qLen:  length of q, in octets, i.e., the smallest integer such that 2^(8qLen) > q
        let bits = Self::ORDER_BITS - Self::ORDER_BITS.leading_zeros() as usize;
        c_string.truncate(bits / 2);

        // 8. c = string_to_int(truncated_c_string)
        // let c = BigNum::from_slice(c_string.as_slice())?;

        Ok(c_string)
    }

    fn try_hash_to_point(&self, data: &[u8]) -> Result<<Self::Curve as elliptic_curve::CurveArithmetic>::AffinePoint> {
        let mut point_bytes = vec![0x02];
        point_bytes.extend(data);

        Self::point_from_bytes(&point_bytes)
    }

    fn point_from_bytes(data: &[u8]) -> Result<<Self::Curve as elliptic_curve::CurveArithmetic>::AffinePoint> {
        // let encoded_point: elliptic_curve::sec1::EncodedPoint<Self::Curve> =
        let encoded_point: elliptic_curve::sec1::EncodedPoint<Self::Curve> =
            elliptic_curve::sec1::EncodedPoint::<Self::Curve>::from_bytes(data)
                .map_err(|e| VrfError::EncodedPoint(e.to_string()))?;

        Option::from(<Self::Curve as elliptic_curve::CurveArithmetic>::AffinePoint::from_encoded_point(&encoded_point))
            .ok_or(VrfError::AffinePoint("invalid encoded point".to_string()))
    }
}

struct P256Sha256;

impl EcVrf for P256Sha256 {
    type Curve = p256::NistP256;
    type Hasher = sha2::Sha256;

    const ORDER_BITS: usize = <Self::Curve as elliptic_curve::Curve>::ORDER.bits();
    const SUITE_ID: u8 = 0x01;
}

struct Secp256k1Sha256;

impl EcVrf for Secp256k1Sha256 {
    type Curve = k256::Secp256k1;
    type Hasher = sha2::Sha256;

    const ORDER_BITS: usize = <Self::Curve as elliptic_curve::Curve>::ORDER.bits();
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

    #[test]
    fn playground() {
        // let x = NistP256::ORDER.bits();
        // let y = k256::Secp256k1::ORDER.bits();
        // println!("====> {}", x)
    }
}
