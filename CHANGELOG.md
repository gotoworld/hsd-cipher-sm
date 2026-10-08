# Changelog

## 2.0.0-SNAPSHOT

Unreleased development version. Formal artifact publication remains subject to ownership, licensing and release checks.

- Replace handwritten production algorithms with Bouncy Castle 1.86; use standard sm2p256v1 for all new operations.
- Remove the fixed SM2 signing nonce and automatic sensitive output. Authenticate C3 before returning plaintext.
- Add strict ciphertext/signature formats, key range and point validation, canonical DER, raw/PEM/PKCS#8/SPKI conversions and explicit precomputed-digest APIs.
- Add read-only historical test-curve decrypt/verify; retain old DER and GBK regression fixtures.
- Correct SM3 copy, offsets, finalization/reset and large-input behavior; add streaming digest and HMAC-SM3.
- Add SM4-GCM, versioned authenticated envelopes, strict ECB/CBC padding and length handling, and non-mutating IV behavior.
- Use UTF-8 and strict character conversion in the deprecated text wrapper; permit explicit historical charsets.
- Unify strict Hex aliases, pin build/test dependencies, package source/Javadoc jars, add independent OpenSSL and standalone-consumer verification.
- Replace obsolete CI with a JDK matrix and dependency update configuration; provide migration, interoperability, security and release documentation.

Breaking changes: remove SM2, Cipher, SM2Result, SM4_Context and handwritten SM3/SM4 internals; change default SM2 curve, text charset and error behavior. See docs/MIGRATION.zh-CN.md.
