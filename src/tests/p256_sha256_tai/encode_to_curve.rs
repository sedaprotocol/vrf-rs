use elliptic_curve::sec1::ToEncodedPoint;

use super::*;

/// Test encode to curve using TAI (try-and-increment) for `P256-SHA256-TAI` cipher suite
#[test]
fn encode_to_curve_tai() {
    let vrf = P256k1Sha256::default();
    let public_key = hex!("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
    let alpha = b"sample";

    let point = vrf.encode_to_curve_tai(&public_key, alpha).unwrap();

    let expected_point = hex!("0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4");
    assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
}
