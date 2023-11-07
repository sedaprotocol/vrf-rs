use super::*;
use crate::P256k1Sha256;

/// Test generate nonce for `P-256` curve with `SHA-256`
/// Message: sample
/// Source: [RFC6979](https://tools.ietf.org/html/rfc6979)
#[test]
fn generate_nonce_1() {
    let vrf = P256k1Sha256::default();
    let secret_key = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let alpha = b"sample";
    let nonce = vrf.generate_nonce(&secret_key, alpha);

    let expected_nonce = hex!("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
    assert_eq!(nonce, expected_nonce.into());
}

/// Test generate nonce for `P-256` curve with `SHA-256`
/// Message: sample
/// Source: [RFC6979](https://tools.ietf.org/html/rfc6979)
#[test]
fn generate_nonce_2() {
    let vrf = P256k1Sha256::default();
    let secret_key = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let alpha = b"test";
    let nonce = vrf.generate_nonce(&secret_key, alpha);

    let expected_nonce = hex!("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0");
    assert_eq!(nonce, expected_nonce.into());
}

/// Test generate nonce for `P-256` curve with `SHA-256`
/// Message: "Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005"
/// Source: [RFC6979](https://tools.ietf.org/html/rfc6979)
#[test]
fn generate_nonce_3() {
    let vrf = P256k1Sha256::default();
    let secret_key = hex!("2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8");
    let alpha = b"Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005";
    let nonce = vrf.generate_nonce(&secret_key, alpha);

    let expected_nonce = hex!("15ee3b7c4f5dfc3c595960a18b4f64a6fe42436f28c158d955e5e2531174dbdb");
    assert_eq!(nonce, expected_nonce.into());
}

/// Test generate nonce for `P-256` curve with `SHA-256`
/// Message: sample
/// Source: [RFC6979](https://tools.ietf.org/html/rfc6979)
#[test]
fn generate_nonce_4() {
    let vrf = P256k1Sha256::default();
    let secret_key = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let alpha = hex!("0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4");
    let nonce = vrf.generate_nonce(&secret_key, &alpha);

    let expected_nonce = hex!("0d90591273453d2dc67312d39914e3a93e194ab47a58cd598886897076986f77");
    assert_eq!(nonce, expected_nonce.into());
}

/// Test generate nonce for `P-256` curve with `SHA-256`
/// Message: sample
/// Source: [RFC6979](https://tools.ietf.org/html/rfc6979)
#[test]
fn generate_nonce_5() {
    let vrf = P256k1Sha256::default();
    let secret_key = hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let alpha = hex!("02173119b4fff5e6f8afed4868a29fe8920f1b54c2cf89cc7b301d0d473de6b974");
    let nonce = vrf.generate_nonce(&secret_key, &alpha);

    let expected_nonce = hex!("5852353a868bdce26938cde1826723e58bf8cb06dd2fed475213ea6f3b12e961");
    assert_eq!(nonce, expected_nonce.into());
}

/// Test generate nonce for `P-256` curve with `SHA-256`
/// Message: "Example using ECDSA key from Appendix L.4.2 of ANSI.X9-62-2005"
/// Source: [RFC6979](https://tools.ietf.org/html/rfc6979)
#[test]
fn generate_nonce_6() {
    let vrf = P256k1Sha256::default();
    let secret_key = hex!("2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8");
    let alpha = hex!("0258055c26c4b01d01c00fb57567955f7d39cd6f6e85fd37c58f696cc6b7aa761d");
    let nonce = vrf.generate_nonce(&secret_key, &alpha);

    let expected_nonce = hex!("5689e2e08e1110b4dda293ac21667eac6db5de4a46a519c73d533f69be2f4da3");
    assert_eq!(nonce, expected_nonce.into());
}
