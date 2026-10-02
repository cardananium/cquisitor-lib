#!/bin/bash
set -e

# Builds the TypeScript library (ts/) into pkg/lib and writes the package entry
# files pkg/index.js + pkg/index.d.ts. Safe to run standalone against an existing
# pkg/: it only ever touches pkg/lib and pkg/index.*, never the wasm outputs.
# post-build.sh assembles pkg/package.json and the wasm layout around it.

PKG_DIR="./pkg"
LIB_DIR="${PKG_DIR}/lib"

# Works both via `npm run lib:build` and when invoked directly.
PATH="$(pwd)/node_modules/.bin:${PATH}"

if [ ! -f ./types/cquisitor_lib.d.ts ]; then
  echo "types/cquisitor_lib.d.ts not found: run 'npm run generate-dts' first."
  exit 1
fi

rm -rf "${LIB_DIR}"
mkdir -p "${PKG_DIR}"
tsc -p tsconfig.lib.json

# Package entry: the root re-exports the library. Kept as files (not just an
# `exports` target) so `main`/`types` work for tools without `exports` support.
cat > "${PKG_DIR}/index.js" <<'JS'
export * from "./lib/index.js";
JS
cat > "${PKG_DIR}/index.d.ts" <<'DTS'
export * from "./lib/index.js";
DTS

# Dev-only self-link. Node and TypeScript resolve the package's own name inside
# pkg/ through pkg/package.json (`name` + `exports`), but a tool that does not
# implement self-reference (or reads pkg/ through a symlink without a package
# scope) finds the package here instead. npm pack never includes node_modules,
# so the link does not ship.
SELF_LINK_DIR="${PKG_DIR}/node_modules/@cardananium"
mkdir -p "${SELF_LINK_DIR}"
ln -sfn ../.. "${SELF_LINK_DIR}/cquisitor-lib"

echo "Built ${LIB_DIR} and ${PKG_DIR}/index.{js,d.ts}"
