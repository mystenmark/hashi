#!/bin/sh
# Runs TLC. Override JAVA or TLA2TOOLS to use other installs.
JAVA=${JAVA:-/opt/homebrew/opt/openjdk@21/bin/java}
JAR=${TLA2TOOLS:-$HOME/.local/share/tla/tla2tools.jar}
exec "$JAVA" -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -cleanup "$@"
