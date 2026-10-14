#!/bin/sh
# Runs TLC. Override JAVA or TLA2TOOLS to use other installs.
# Each run gets its own metadata directory so concurrent runs do not collide.
JAVA=${JAVA:-/opt/homebrew/opt/openjdk@21/bin/java}
JAR=${TLA2TOOLS:-$HOME/.local/share/tla/tla2tools.jar}
META=$(mktemp -d "${TMPDIR:-/tmp}/tlc-states.XXXXXX")
"$JAVA" -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -metadir "$META" "$@"
status=$?
rm -rf "$META"
exit $status
