#!/usr/bin/env bash
set -euo pipefail

git config --global --add safe.directory "${PWD}" || true

gradle_home="${GRADLE_USER_HOME:-${HOME}/.gradle}"
mkdir -p "${gradle_home}"
cat > "${gradle_home}/gradle.properties" <<EOF
org.gradle.java.installations.paths=${JAVA_HOME}
jipher.openssl.useOsInstance=true
EOF

run_gradle() {
  sed 's/\r$//' ./gradlew | sh -s -- "$@"
}

run_gradle --no-daemon --version
run_gradle --no-daemon jar jipherTestJar testClasses intTestClasses systemTestClasses leakTestClasses