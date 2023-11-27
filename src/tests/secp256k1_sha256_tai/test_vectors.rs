use std::{fs::File, path::Path};

use super::*;

/// Test vectors extracted from an OpenSSL implementation
#[test]
fn prove_verify() {
    let json_file_path = Path::new("./src/tests/secp256k1_sha256_tai/ECVRF_SECP256K1_SHA256_TAI.json");
    let file = File::open(json_file_path).unwrap();
    let test_vectors: Vec<serde_json::Value> = serde_json::from_reader(file).expect("JSON was not well-formatted");

    for (index, test_vector) in test_vectors.iter().enumerate() {
        let secret_key = hex::decode(test_vector.get("priv").unwrap().as_str().unwrap()).unwrap();
        let public_key: Vec<u8> = hex::decode(test_vector.get("pub").unwrap().as_str().unwrap()).unwrap();
        let alpha = hex::decode(test_vector.get("message").unwrap().as_str().unwrap()).unwrap();
        let pi: Vec<u8> = hex::decode(test_vector.get("pi").unwrap().as_str().unwrap()).unwrap();
        let beta = hex::decode(test_vector.get("hash").unwrap().as_str().unwrap()).unwrap();

        let vrf = Secp256k1Sha256::default();

        let result_prove = vrf.prove(&secret_key, &alpha);
        assert!(result_prove.is_ok(), "Prove failed (test vector #{})", index);
        assert_eq!(
            result_prove.unwrap(),
            pi,
            "Prove output does not match (test vector #{})",
            index
        );

        let result_verify = vrf.verify(&public_key, &pi, &alpha);
        assert!(result_verify.is_ok(), "Verify failed (test vector #{})", index);
        assert_eq!(
            result_verify.unwrap().to_vec(),
            beta,
            "Verify output does not match (test vector #{})",
            index
        );
    }
}
