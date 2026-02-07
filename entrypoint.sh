#!/bin/bash
set -e

# Start building the command
CMD="janitor $INPUT_COMMAND $INPUT_PATH"

# Add flags based on inputs
if [ -n "$INPUT_LANGUAGE" ]; then
  CMD="$CMD --language $INPUT_LANGUAGE"
fi

if [ "$INPUT_LIBRARY" == "true" ]; then
  CMD="$CMD --library"
fi

if [ "$INPUT_INCLUDE_VENDORED" == "true" ]; then
  CMD="$CMD --include-vendored"
fi

# Add command-specific flags
if [ "$INPUT_COMMAND" == "clean" ]; then
  if [ -n "$INPUT_MODE" ]; then
    CMD="$CMD --mode $INPUT_MODE"
  fi
  # For GitHub Actions, we usually want auto-confirmation
  CMD="$CMD --yes"
fi

if [ "$INPUT_COMMAND" == "dedup" ]; then
  if [ -n "$INPUT_THRESHOLD" ]; then
    CMD="$CMD --threshold $INPUT_THRESHOLD"
  fi
fi

# Execute
echo "Runnning: $CMD"
eval "$CMD"