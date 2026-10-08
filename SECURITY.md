# Security Policy

## System and Scope

This repository is an in-process Java cryptography integration library, not a network service or a key-management system. Production code is under `src/main/java`; standard SM2, SM3, HMAC-SM3 and SM4 operations use Bouncy Castle. The `legacy` package reads historical test-curve ciphertext and verifies historical signatures; it must never generate new historical-curve signatures or ciphertext.

2.0.0-SNAPSHOT is an unreleased development version. Historical 1.0-SNAPSHOT signing used a public fixed nonce and printed private keys; its decrypt path omitted C3 verification. Keys used by that signing path require rotation. Historical verification cannot restore the trustworthiness of those signatures or the confidentiality of those keys.

## Threat Model and Trust Boundaries

Ciphertexts, signatures, encoded key files, identifiers and wire-format inputs may be attacker-controlled. Raw secret keys are supplied by the application. Applications remain responsible for access control, selecting trusted keys, limiting request/file sizes, secret storage and rotation. A GCM envelope key ID is untrusted until authentication succeeds; key routing must not grant permissions or cross tenant boundaries.

There is no confirmed internet deployment or hardware boundary in this repository. A finding should describe the reachable library entry point and realistic caller behavior; do not assume a remote endpoint exists. The absence of an endpoint does not excuse broken cryptographic properties reachable through the public API.

## Security Invariants

- Signing and encryption use fresh cryptographic randomness. No production fixed nonce, caller-selectable signing nonce or automatic secret/message logging is permitted.
- SM2 and GCM decryption return plaintext only after integrity/authentication verification. No public alternate path may expose unauthenticated partial plaintext.
- Key scalars, public points, signature ranges, DER structure, field types and lengths are validated before use. Equivalent malformed encodings must not bypass validation.
- Standard operations use sm2p256v1. Legacy curve selection is explicit and read-only; formats and charsets are never automatically guessed.
- SM4 padding and block lengths are validated. ECB/CBC are explicit interoperability primitives and are not described as authenticated encryption.
- String encoding must not silently replace characters. Digest copies and finalization preserve complete state and do not truncate message lengths.
- AAD, GCM envelope metadata and tags are authenticated. Unknown envelope versions/algorithms are rejected, and low-level GCM callers must ensure nonce uniqueness for each key.
- Stateless APIs do not mutate caller buffers or register a JVM-global provider. Mutable compatibility wrappers and digest objects are not shared between threads.

## Reportable Findings and Severity Context

Reachable private-key disclosure/recovery, signature acceptance outside the specified verification rules, authentication bypass, cross-format validation bypass and meaningful input-driven denial of service are relevant. Explain the source-to-use path, affected entry points, required conditions, confidentiality/integrity impact and a non-production reproduction. Do not infer arbitrary signature forgery solely from accepting a noncanonical signature, or a remote padding oracle solely from a local exception.

No owner-confirmed finding exclusions or risk exemptions have been established. Historical probes and fixtures describe intentionally retained evidence, but their presence must not be used to suppress a reachable production path.

## Limitations and Application Responsibilities

Tests and interoperability results are evidence for their declared cases, not certification or proof against every attack. Side-channel resistance, JVM memory erasure, hardware integration, TLS protocols and operating-system key protection have not been independently assessed. Java arrays, strings and BigInteger values do not provide guaranteed secret erasure.

`seal` uses random 96-bit GCM nonces. Random generation cannot guarantee absence of collisions over unlimited use. Applications must limit per-key message volume and rotate keys; applications requiring a coordinated deterministic nonce scheme must manage it outside the library and use the explicit GCM API. Never reuse a nonce under the same key.

Applications should expose a uniform failure response to remote callers rather than returning parser, padding or authentication causes. They should impose protocol-appropriate size limits before passing untrusted data to byte-array APIs. This library does not authenticate historical unauthenticated CBC records or make compromised old signing keys safe.

## Reporting and Release Status

Use the repository's **Report a vulnerability** channel if GitHub private vulnerability reporting is enabled. Do not publish live keys, application plaintext or unremediated exploit details in public issues. A verified private contact and response policy still need maintainer confirmation before public release; this document does not invent an email address or claim the channel is enabled.

Public release also requires ownership, contribution permissions, project licensing and Maven namespace authorization. See `docs/RELEASING.zh-CN.md`. This development branch does not constitute a formal package release. Historical security issues are documented for migration and release communication.
