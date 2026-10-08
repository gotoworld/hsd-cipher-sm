#!/usr/bin/env bash
# Run after installing the root project into the same local Maven repository.
# Additional Maven flags (e.g. -Dmaven.repo.local=/tmp/cache) may be passed as arguments.
set -euo pipefail
example_dir="$(cd "$(dirname "$0")" && pwd)"
mvn -B -f "$example_dir/pom.xml" "$@" compile dependency:build-classpath -Dmdep.outputFile=target/classpath.txt
example_classpath="$(cat "$example_dir/target/classpath.txt")"
java -cp "$example_dir/target/classes:$example_classpath" com.heshidai.security.cipher.examples.QuickStart
