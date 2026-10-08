#!/usr/bin/env bash
# Reproduce the reviewed legacy behavior; this is not a release acceptance suite.
# Usage:
#   LEGACY_JAVA_HOME=/path/to/jdk8 REFERENCE_JAVA_HOME=/path/to/jdk17 \
#     bash docs/maintenance-review/run-probes.sh \
#       /path/to/bcprov-jdk16-1.46.jar /path/to/bcprov-jdk18on-1.86.jar
# Dependencies are intentionally not downloaded by this script.
# Observed SHA-256 values for the reviewed Maven Central artifacts:
# 1.46: 10ef7403392d4cda22b200a7a9a620dc258b5aa6a56d24a2fea468e324dab2c9
# 1.86: 2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'Expected paths to the legacy BC 1.46 jar and reference BC 1.86 jar.' >&2
  exit 2
fi
: "${LEGACY_JAVA_HOME:?Set LEGACY_JAVA_HOME to a JDK 8 installation}"
: "${REFERENCE_JAVA_HOME:?Set REFERENCE_JAVA_HOME to a JDK 17 or later installation}"

review_dir="$(cd "$(dirname "$0")" && pwd)"
review_repo="$(cd "$review_dir/../.." && pwd)"
review_legacy_jar="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
review_reference_jar="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
review_work="$(mktemp -d "${TMPDIR:-/tmp}/hsd-cipher-probes.XXXXXX")"
mkdir -p "$review_work/legacy" "$review_work/reference"
mkdir -p "$review_work/original"
# The working tree has been repaired. Always reproduce the immutable historical revision.
review_commit=f1af537ab46215446dd04918179440a9b08b1615
git -C "$review_repo" archive "$review_commit" src/main/java | tar -xf - -C "$review_work/original"

"$LEGACY_JAVA_HOME/bin/javac" -encoding UTF-8 -cp "$review_legacy_jar" \
  -d "$review_work/legacy" "$review_work/original"/src/main/java/com/heshidai/security/cipher/*.java
"$LEGACY_JAVA_HOME/bin/javac" -encoding UTF-8 \
  -cp "$review_work/legacy:$review_legacy_jar" -d "$review_work/legacy" "$review_dir/LegacyProbe.java"
"$LEGACY_JAVA_HOME/bin/java" -cp "$review_work/legacy:$review_legacy_jar" LegacyProbe \
  > "$review_work/legacy-results.txt"

"$REFERENCE_JAVA_HOME/bin/javac" -encoding UTF-8 -cp "$review_reference_jar" \
  -d "$review_work/reference" "$review_dir/ReferenceProbe.java"
"$REFERENCE_JAVA_HOME/bin/java" -cp "$review_work/reference:$review_reference_jar" ReferenceProbe \
  > "$review_work/reference-results.txt"

python3 - "$review_work" <<'PY'
import pathlib
import sys

work = pathlib.Path(sys.argv[1])
def read(name):
    return dict(line.split('=', 1) for line in (work / name).read_text().splitlines())

legacy = read('legacy-results.txt')
reference = read('reference-results.txt')
shared = sorted(legacy.keys() & reference.keys())
assert len(shared) == 14, shared
for key in shared:
    assert legacy[key] == reference[key], (key, legacy[key], reference[key])
assert reference['reference_provider'] == '1.86', reference['reference_provider']
assert legacy['sm3_abc'] == '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
assert legacy['sm4_standard_vector'] == '681edf34d206965e86b3e94f536e4246'

expected_legacy_behavior = {
    'sm2_private_key_recovered_from_one_signature': 'true',
    'sm2_private_key_written_to_stdout': 'true',
    'sm2_same_message_same_signature': 'true',
    'sm2_original_signature_verifies': 'true',
    'sm2_signature_with_s_plus_n_accepted': 'true',
    'sm2_valid_high_bit_private_key_verifies': 'false',
    'sm2_original_ciphertext_roundtrip': 'true',
    'sm2_changed_c3_accepted': 'true',
    'sm2_changed_c2_returns_predictably_changed_plaintext': 'true',
    'sm2_empty_plaintext_returns_null': 'true',
    'sm3_six_chunk_sizes_match_one_shot': 'true',
    'sm3_out_offset_honored': 'false',
    'sm3_copy_after_processed_block_matches': 'false',
    'sm3_doFinal_resets_for_reuse': 'false',
    'sm3_256MiB_length_field': 'FFFFFFFF80000000',
    'sm4_invalid_padding_accepted': 'true',
    'sm4_zero_padding_accepted': 'true',
    'sm4_truncated_block_accepted': 'true',
    'sm4_cbc_mutates_caller_iv': 'true',
    'sm4_unicode_roundtrip': 'false',
    'hex_odd_length_silently_truncated': 'true',
    'hex_non_hex_accepted': 'true',
}
for key, expected in expected_legacy_behavior.items():
    assert legacy[key] == expected, (key, legacy[key], expected)

print('Reproduced 22 legacy behavior checks; 14 differential outputs match BC 1.86.')
print('These checks reproduce old defects. They do not indicate production readiness.')
print('Results: ' + str(work))
PY
