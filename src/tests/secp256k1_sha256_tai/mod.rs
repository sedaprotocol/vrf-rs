use elliptic_curve::sec1::ToEncodedPoint;

use super::*;
use crate::Secp256k1Sha256;

mod test_vectors;

/// Test VRF decode proof for `SECP256K1-SHA256-TAI` cipher suite
#[test]
fn decode_proof() {
    let vrf = Secp256k1Sha256::default();
    let pi = hex!(
        "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f"
    );
    let (gamma, c, s) = vrf.decode_proof(&pi).unwrap();

    let expected_gamma = hex!("035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4");
    let expected_c = hex!("00000000000000000000000000000000a53f0a46f018bc2c56e58d383f2305e0");
    let expected_s = hex!("975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f");

    assert_eq!(gamma, expected_gamma);
    assert_eq!(c, expected_c);
    assert_eq!(s, expected_s);
}

/// Test encode to curve using TAI (try-and-increment) for `SECP256K1-SHA256-TAI` cipher suite
#[test]
fn encode_to_curve_tai() {
    let vrf = Secp256k1Sha256::default();
    let public_key = hex!("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645");
    let alpha = b"sample";

    let point = vrf.encode_to_curve_tai(&public_key, alpha).unwrap();

    let expected_point = hex!("0221ceb1ce22cd34d8b73a619164ed64e917ca31fd454075d02e4bdfa9c5ce0b48");
    assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
}

/// Test VRF prove for `SECP256K1-SHA256-TAI` cipher suite
/// ASCII: "sample"
#[test]
fn prove() {
    let vrf = Secp256k1Sha256::default();
    let secret_key = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
    let alpha = b"sample";
    let pi = vrf.prove(&secret_key, alpha).unwrap();

    let expected_pi = hex!(
            "03cc8a4f11c8dde5cbaad50f523c43389aa9eb407288570cf2bcd2e524ac0cbf88123d52707735b2ecff030dbdd71ac3a20166e4fb77f254dae61c6a35c694e539ae2d51e2ffce166cc455386aadb28bad"
        ).to_vec();
    assert_eq!(pi, expected_pi);
}

/// Test VRF verify for `SECP256K1-SHA256-TAI` cipher suite
/// ASCII: "sample"
#[test]
fn verify() {
    let vrf = Secp256k1Sha256::default();
    let public_key = hex!("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645");
    let alpha = b"sample";
    let pi = hex!(
        "0338ec99b5d0f94ebcc2c704c04af3de8b4289df8798e5fb9f920d7f5d77ac03d7718b9677d1c9348649ac2ec4f7ecbe519b30dd10c4eb5efc21dd5944709f2f3b7e97a25f6f095334593502d05103bc5b"
    );
    let beta = vrf.verify(&public_key, &pi, alpha).unwrap();

    let expected_beta = hex!("d466c22e14dc3b7fd169668dd3ee9ac6351429a24aebc5e8af61a0f0de89b65a");
    assert_eq!(beta.as_slice(), expected_beta);
    assert_eq!(vrf.proof_to_hash(&pi).unwrap(), expected_beta.into());
}
