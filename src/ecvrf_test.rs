use elliptic_curve::sec1::ToEncodedPoint;
use hex_literal::hex;
use sha2::Digest;

use crate::{P256k1Sha256, Secp256k1Sha256};

/// Test VRF prove for `P256-SHA256-TAI` cipher suite
/// ASCII: "sample"
/// Source: Example 10 (RFC9381, Appendix B.1)
#[test]
fn test_prove_p256_sha256_tai_1() {
    let vrf = P256k1Sha256::default();
    let secret_key = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let alpha = b"sample";
    let pi = vrf.prove(&secret_key, alpha).unwrap();

    let expected_pi = hex!(
            "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f"
        ).to_vec();
    assert_eq!(pi, expected_pi);
}

/// Test VRF verify for `P256-SHA256-TAI` cipher suite
/// ASCII: "sample"
/// Source: Example 10 (RFC9381, Appendix B.1)
#[test]
fn test_verify_p256_sha256_tai_1() {
    let vrf = P256k1Sha256::default();
    let public_key = hex!("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
    let alpha = b"sample";
    let pi = hex!(
        "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4a53f0a46f018bc2c56e58d383f2305e0975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f"
    );
    let beta = vrf.verify(&public_key, &pi, alpha).unwrap();

    let expected_beta = hex!("a3ad7b0ef73d8fc6655053ea22f9bede8c743f08bbed3d38821f0e16474b505e");
    assert_eq!(beta.as_slice(), expected_beta);
}

/// Test VRF prove for `P256-SHA256-TAI` cipher suite
/// ASCII: "test"
/// Source: Example 11 (RFC9381, Appendix B.1)
#[test]
fn test_prove_p256_sha256_tai_2() {
    let vrf = P256k1Sha256::default();
    let secret_key = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let alpha = b"test";
    let pi = vrf.prove(&secret_key, alpha).unwrap();

    let expected_pi = hex!(
            "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb56c19e067b15a8a8174905b13617804534214f935b94c2287f797e393eb0816969d864f37625b443f30f1a5a33f2b3c854"
        ).to_vec();
    assert_eq!(pi, expected_pi);
}

/// Test VRF verify for `P256-SHA256-TAI` cipher suite
/// ASCII: "test"
/// Source: Example 11 (RFC9381, Appendix B.1)
#[test]
fn test_verify_p256_sha256_tai_2() {
    let vrf = P256k1Sha256::default();
    let public_key = hex!("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
    let alpha = b"test";
    let pi = hex!(
        "034dac60aba508ba0c01aa9be80377ebd7562c4a52d74722e0abae7dc3080ddb56c19e067b15a8a8174905b13617804534214f935b94c2287f797e393eb0816969d864f37625b443f30f1a5a33f2b3c854"
    );
    let beta = vrf.verify(&public_key, &pi, alpha).unwrap();

    let expected_beta = hex!("a284f94ceec2ff4b3794629da7cbafa49121972671b466cab4ce170aa365f26d");
    assert_eq!(beta.as_slice(), expected_beta);
}

/// Test VRF prove for `P256-SHA256-TAI` cipher suite
/// ASCII: "Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005"
/// Source: Example 12 (RFC9381, Appendix B.1)
#[test]
fn test_prove_p256_sha256_tai_3() {
    let vrf = P256k1Sha256::default();
    let secret_key = hex!("2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8");
    let alpha = b"Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005";
    let pi = vrf.prove(&secret_key, alpha).unwrap();

    let expected_pi = hex!(
            "03d03398bf53aa23831d7d1b2937e005fb0062cbefa06796579f2a1fc7e7b8c667d091c00b0f5c3619d10ecea44363b5a599cadc5b2957e223fec62e81f7b4825fc799a771a3d7334b9186bdbee87316b1"
        ).to_vec();
    assert_eq!(pi, expected_pi);
}

/// Test VRF verify for `P256-SHA256-TAI` cipher suite
/// ASCII: "Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005"
/// Source: Example 12 (RFC9381, Appendix B.1)
#[test]
fn test_verify_p256_sha256_tai_3() {
    let vrf = P256k1Sha256::default();
    let public_key = hex!("03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d");
    let alpha = b"Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005";
    let pi = hex!(
        "03d03398bf53aa23831d7d1b2937e005fb0062cbefa06796579f2a1fc7e7b8c667d091c00b0f5c3619d10ecea44363b5a599cadc5b2957e223fec62e81f7b4825fc799a771a3d7334b9186bdbee87316b1"
    );
    let beta = vrf.verify(&public_key, &pi, alpha).unwrap();

    let expected_beta = hex!("90871e06da5caa39a3c61578ebb844de8635e27ac0b13e829997d0d95dd98c19");
    assert_eq!(beta.as_slice(), expected_beta);
}

/// Same as `p256_sha256_tai_encode_to_curve_1`
#[test]
fn test_decode_proof() {
    let vrf = Secp256k1Sha256::default();

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

#[test]
fn secp256k1_sha256_tai_encode_to_curve() {
    let vrf = Secp256k1Sha256::default();
    let public_key = hex!("032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645");
    let alpha = b"sample";

    let point = vrf.encode_to_curve_tai(&public_key, alpha).unwrap();

    let expected_point = hex!("0221ceb1ce22cd34d8b73a619164ed64e917ca31fd454075d02e4bdfa9c5ce0b48");
    assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
}

#[test]
fn p256_sha256_tai_encode_to_curve() {
    let vrf = P256k1Sha256::default();
    let public_key = hex!("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
    let alpha = b"sample";

    let point = vrf.encode_to_curve_tai(&public_key, alpha).unwrap();

    let expected_point = hex!("0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4");
    assert_eq!(point.to_encoded_point(true).as_bytes(), expected_point);
}

/// Source: RFC 6979 (A.2.5.  ECDSA, 256 Bits (Prime Field))
#[test]
fn test_nonce_generation() {
    let vrf = Secp256k1Sha256::default();
    let secret_key = hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let alpha = b"sample";
    let k = vrf.generate_nonce(&secret_key, &sha2::Sha256::digest(alpha)).unwrap();

    let expected_k = hex!("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
    assert_eq!(k.to_bytes().as_slice(), &expected_k);
}
