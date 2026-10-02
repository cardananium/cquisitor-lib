#!/bin/bash
set -e

# Assembles the publishable package in pkg/ from the wasm-pack outputs
# (pkg/node, pkg/browser: `npm run rust:build-wasm`) and the TypeScript build
# (pkg/lib + pkg/index.*: `npm run lib:build`):
#
#   pkg/package.json            written here, version from the wasm-pack manifest
#   pkg/index.js, index.d.ts    -> ./lib/index.js (from build-lib.sh)
#   pkg/lib/**                  the library (ESM + .d.ts)
#   pkg/wasm/node/              cquisitor_lib.cjs (+ .d.cts), cquisitor_lib_bg.wasm
#   pkg/wasm/browser/           cquisitor_lib.js, cquisitor_lib_bg.js, cquisitor_lib_bg.wasm (+ .d.ts,
#                               cquisitor_lib_bg.d.ts for hosts that instantiate the wasm by hand)
#   pkg/README.md, LICENSE
#
# The root is ESM (`"type": "module"`), so the CommonJS node glue is renamed to
# .cjs; the .wasm keeps its name because the glue reads `__dirname/cquisitor_lib_bg.wasm`.
# No nested package.json anywhere in pkg/: a nameless nested scope breaks
# TypeScript's and Node's package self-reference for the .d.ts/.js under it.
#
# Idempotent: a re-run against an already assembled pkg/ (pkg/node and
# pkg/browser gone, pkg/wasm/* present) rewrites package.json and the entry files
# and leaves the wasm where it is.

PKG_DIR="./pkg"
NODE_SRC="${PKG_DIR}/node"
BROWSER_SRC="${PKG_DIR}/browser"
WASM_DIR="${PKG_DIR}/wasm"
NODE_DIR="${WASM_DIR}/node"
BROWSER_DIR="${WASM_DIR}/browser"
LIB_DIR="${PKG_DIR}/lib"
TYPES_DTS="./types/cquisitor_lib.d.ts"

fail() { echo "post-build: $*" >&2; exit 1; }

# ---- preflight: everything must exist before pkg/ is mutated ----
command -v jq >/dev/null 2>&1 || fail "jq is not installed."
[ -f "${TYPES_DTS}" ] || fail "${TYPES_DTS} not found: run 'npm run generate-dts' first."
[ -f "${LIB_DIR}/index.js" ] || fail "${LIB_DIR}/index.js not found: run 'npm run lib:build' first."
[ -f "${LIB_DIR}/wasm/load.js" ] || fail "${LIB_DIR}/wasm/load.js not found: pkg/lib is stale, run 'npm run lib:build'."

if [ -f "${NODE_SRC}/cquisitor_lib.js" ]; then
  [ -f "${NODE_SRC}/cquisitor_lib_bg.wasm" ] || fail "${NODE_SRC}/cquisitor_lib_bg.wasm missing."
  HAVE_NODE_SRC=1
elif [ -f "${NODE_DIR}/cquisitor_lib.cjs" ] && [ -f "${NODE_DIR}/cquisitor_lib_bg.wasm" ]; then
  HAVE_NODE_SRC=0
else
  fail "no node wasm build: run 'npm run rust:build-wasm:node' (expected ${NODE_SRC}/cquisitor_lib.js)."
fi

if [ -f "${BROWSER_SRC}/cquisitor_lib.js" ]; then
  [ -f "${BROWSER_SRC}/cquisitor_lib_bg.js" ] || fail "${BROWSER_SRC}/cquisitor_lib_bg.js missing (bundler-target glue)."
  [ -f "${BROWSER_SRC}/cquisitor_lib_bg.wasm" ] || fail "${BROWSER_SRC}/cquisitor_lib_bg.wasm missing."
  HAVE_BROWSER_SRC=1
elif [ -f "${BROWSER_DIR}/cquisitor_lib.js" ] && [ -f "${BROWSER_DIR}/cquisitor_lib_bg.wasm" ]; then
  HAVE_BROWSER_SRC=0
else
  fail "no browser wasm build: run 'npm run rust:build-wasm:browser' (expected ${BROWSER_SRC}/cquisitor_lib.js)."
fi

# ---- version: the wasm-pack manifest carries Cargo.toml's version ----
# A fresh wasm build brings pkg/node/package.json; a re-run keeps what the
# previous assembly wrote; a pkg/ without either falls back to Cargo.toml.
if [ -f "${NODE_SRC}/package.json" ]; then
  MANIFEST="${NODE_SRC}/package.json"
elif [ -f "${PKG_DIR}/package.json" ]; then
  MANIFEST="${PKG_DIR}/package.json"
else
  MANIFEST=""
fi
if [ -n "${MANIFEST}" ]; then
  VERSION=$(jq -r '.version' "${MANIFEST}")
  DESCRIPTION=$(jq -r '.description // empty' "${MANIFEST}")
  LICENSE=$(jq -r '.license // empty' "${MANIFEST}")
  COLLABORATORS=$(jq -c '.collaborators // []' "${MANIFEST}")
  REPOSITORY=$(jq -c '.repository // null' "${MANIFEST}")
  echo "Version ${VERSION} from ${MANIFEST}"
else
  VERSION=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)
  DESCRIPTION=$(sed -n 's/^description *= *"\(.*\)"/\1/p' Cargo.toml | head -1)
  LICENSE=$(sed -n 's/^license *= *"\(.*\)"/\1/p' Cargo.toml | head -1)
  COLLABORATORS='[]'
  REPOSITORY='null'
  echo "Version ${VERSION} from Cargo.toml"
fi
[ -n "${VERSION}" ] && [ "${VERSION}" != "null" ] || fail "could not determine the package version."
PACKAGE_NAME=$(jq -r '.name' package.json)

# ---- previous layout (pkg/core with its own package.json) must not linger ----
rm -rf "${PKG_DIR}/core"

# ---- wasm layout ----
mkdir -p "${NODE_DIR}" "${BROWSER_DIR}"
if [ "${HAVE_NODE_SRC}" = 1 ]; then
  rm -rf "${NODE_DIR}"
  mkdir -p "${NODE_DIR}"
  mv "${NODE_SRC}/cquisitor_lib.js" "${NODE_DIR}/cquisitor_lib.cjs"
  mv "${NODE_SRC}/cquisitor_lib_bg.wasm" "${NODE_DIR}/cquisitor_lib_bg.wasm"
  [ -f "${NODE_SRC}/cquisitor_lib_bg.wasm.d.ts" ] && mv "${NODE_SRC}/cquisitor_lib_bg.wasm.d.ts" "${NODE_DIR}/cquisitor_lib_bg.wasm.d.ts"
  [ -f "${NODE_SRC}/LICENSE" ] && cp "${NODE_SRC}/LICENSE" "${PKG_DIR}/LICENSE"
  rm -rf "${NODE_SRC}"
  echo "Moved the node wasm build to ${NODE_DIR} (glue renamed to .cjs)"
fi
if [ "${HAVE_BROWSER_SRC}" = 1 ]; then
  rm -rf "${BROWSER_DIR}"
  mkdir -p "${BROWSER_DIR}"
  mv "${BROWSER_SRC}/cquisitor_lib.js" "${BROWSER_DIR}/cquisitor_lib.js"
  mv "${BROWSER_SRC}/cquisitor_lib_bg.js" "${BROWSER_DIR}/cquisitor_lib_bg.js"
  mv "${BROWSER_SRC}/cquisitor_lib_bg.wasm" "${BROWSER_DIR}/cquisitor_lib_bg.wasm"
  [ -f "${BROWSER_SRC}/cquisitor_lib_bg.wasm.d.ts" ] && mv "${BROWSER_SRC}/cquisitor_lib_bg.wasm.d.ts" "${BROWSER_DIR}/cquisitor_lib_bg.wasm.d.ts"
  [ -f "${PKG_DIR}/LICENSE" ] || { [ -f "${BROWSER_SRC}/LICENSE" ] && cp "${BROWSER_SRC}/LICENSE" "${PKG_DIR}/LICENSE"; }
  rm -rf "${BROWSER_SRC}"
  echo "Moved the browser wasm build to ${BROWSER_DIR}"
fi
[ -f "${PKG_DIR}/LICENSE" ] || cp ./LICENSE "${PKG_DIR}/LICENSE"

# The hand-maintained + schema-generated declarations replace wasm-pack's in both
# builds (.d.cts next to the CommonJS glue, .d.ts next to the ESM glue).
cp "${TYPES_DTS}" "${NODE_DIR}/cquisitor_lib.d.cts"
cp "${TYPES_DTS}" "${BROWSER_DIR}/cquisitor_lib.d.ts"
echo "Installed types/cquisitor_lib.d.ts as ${NODE_DIR}/cquisitor_lib.d.cts and ${BROWSER_DIR}/cquisitor_lib.d.ts"

# The bundler glue's inner module (`./wasm/browser/cquisitor_lib_bg.js`), which a
# host without wasm ESM integration imports to instantiate the wasm itself
# (README, "Without a plugin"): every export of the glue, plus the hook that
# hands it the instantiated module.
cat > "${BROWSER_DIR}/cquisitor_lib_bg.d.ts" <<'DTS'
// Types of the bundler glue's inner module, for hosts that instantiate the wasm
// by hand: every function the package's `./wasm` exports, plus `__wbg_set_wasm`,
// which takes the instantiated module's exports. The wasm's imports are this
// module itself, under the name "./cquisitor_lib_bg.js".
export * from "./cquisitor_lib.js";
export function __wbg_set_wasm(exports: object): void;
DTS

# Nothing but the files above may live under pkg/wasm (no wasm-pack manifests).
find "${WASM_DIR}" -name package.json -delete
find "${WASM_DIR}" -name README.md -delete
find "${WASM_DIR}" -name .gitignore -delete
find "${WASM_DIR}" -name LICENSE -delete

# ---- entry files (build-lib.sh writes them too; make sure they are there) ----
[ -f "${PKG_DIR}/index.js" ] || echo 'export * from "./lib/index.js";' > "${PKG_DIR}/index.js"
[ -f "${PKG_DIR}/index.d.ts" ] || echo 'export * from "./lib/index.js";' > "${PKG_DIR}/index.d.ts"

# ---- README, publish config ----
cp ./README.md "${PKG_DIR}/README.md"
# .npmrc is gitignored (publish config); absent on CI checkouts.
[ -f .npmrc ] && cp .npmrc "${PKG_DIR}/.npmrc"

# ---- package.json ----
LIB_GROUPS='["chain","share","cddl","worker","util","handoff","types"]'
TMPFILE=$(mktemp)
jq -n \
  --arg name "${PACKAGE_NAME}" \
  --arg version "${VERSION}" \
  --arg description "${DESCRIPTION}" \
  --arg license "${LICENSE}" \
  --argjson collaborators "${COLLABORATORS}" \
  --argjson repository "${REPOSITORY}" \
  --argjson groups "${LIB_GROUPS}" '
  # exports for one group: the barrel and every module under it
  def group_exports($g):
    { ("./" + $g): { "types": ("./lib/" + $g + "/index.d.ts"), "default": ("./lib/" + $g + "/index.js") },
      ("./" + $g + "/*"): { "types": ("./lib/" + $g + "/*.d.ts"), "default": ("./lib/" + $g + "/*.js") } };
  {
    name: $name,
    version: $version,
    description: $description,
    license: $license,
    type: "module",
    main: "./index.js",
    types: "./index.d.ts",
    # Each runtime condition names its own declarations: the CommonJS node glue
    # is typed by the .d.cts, the ESM browser glue by the .d.ts, so TypeScript
    # under node16/nodenext sees the module format Node will load.
    # TypeScript under `moduleResolution: "bundler"` sets neither `node` nor
    # `browser`, only `import`: it gets the ESM .d.ts (named exports, no
    # default), the one shape both runtime files honour, so a default import
    # that the browser glue lacks fails at type-check rather than at bundle
    # time. The file a runtime loads under `default` is unchanged.
    exports: ({
      ".": { "types": "./index.d.ts", "default": "./index.js" },
      "./wasm": {
        "node": { "types": "./wasm/node/cquisitor_lib.d.cts", "default": "./wasm/node/cquisitor_lib.cjs" },
        "browser": { "types": "./wasm/browser/cquisitor_lib.d.ts", "default": "./wasm/browser/cquisitor_lib.js" },
        "default": {
          "import": { "types": "./wasm/browser/cquisitor_lib.d.ts", "default": "./wasm/node/cquisitor_lib.cjs" },
          "types": "./wasm/node/cquisitor_lib.d.cts",
          "default": "./wasm/node/cquisitor_lib.cjs"
        }
      },
      # The browser glue file by file, for instantiating the wasm by hand.
      "./wasm/browser/*": "./wasm/browser/*",
      "./node": { "types": "./lib/node/index.d.ts", "default": "./lib/node/index.js" },
      "./node/*": { "types": "./lib/node/*.d.ts", "default": "./lib/node/*.js" }
    } + ([ $groups[] | group_exports(.) ] | add)
      + { "./package.json": "./package.json" }),
    # Legacy `moduleResolution: node10` cannot read `exports`; give it the same
    # subpath -> declaration map through typesVersions.
    typesVersions: { "*": ({
      "wasm": ["./wasm/browser/cquisitor_lib.d.ts"],
      "wasm/browser/*": ["./wasm/browser/*"],
      "node": ["./lib/node/index.d.ts"],
      "node/*": ["./lib/node/*.d.ts"]
    } + ([ $groups[] | { (.): ["./lib/" + . + "/index.d.ts"], (. + "/*"): ["./lib/" + . + "/*.d.ts"] } ] | add)) },
    files: ["index.js", "index.d.ts", "lib/**", "wasm/**", "README.md", "LICENSE"],
    # Only the wasm glue runs code at import time (it instantiates the module);
    # the worker entry starts serving when loaded as a worker.
    sideEffects: ["./wasm/**/*.js", "./wasm/**/*.cjs", "./lib/node/wasmWorker.js"],
    dependencies: { "bech32": "^2.0.0", "safe-stable-stringify": "^2.5.0" },
    engines: { "node": ">=20" },
    keywords: ["cardano", "cbor", "cddl", "plutus", "transaction", "validation", "wasm"]
  }
  | if ($collaborators | length) > 0 then . + { collaborators: $collaborators } else . end
  | if $repository != null then . + { repository: $repository } else . end
' > "${TMPFILE}"
mv "${TMPFILE}" "${PKG_DIR}/package.json"
echo "Wrote ${PKG_DIR}/package.json (${PACKAGE_NAME}@${VERSION})"

# ---- postflight: every exports target must exist ----
MISSING=0
for target in $(jq -r '.exports | .. | strings' "${PKG_DIR}/package.json" | grep -v '\*' | sort -u); do
  if [ ! -f "${PKG_DIR}/${target}" ]; then
    echo "post-build: exports target ${target} does not exist" >&2
    MISSING=1
  fi
done
for group in $(echo "${LIB_GROUPS}" | jq -r '.[]'); do
  [ -f "${LIB_DIR}/${group}/index.js" ] || { echo "post-build: ${LIB_DIR}/${group}/index.js missing" >&2; MISSING=1; }
done
# The worker_threads entry createNodeWorkerBackend spawns.
[ -f "${LIB_DIR}/node/wasmWorker.js" ] || { echo "post-build: ${LIB_DIR}/node/wasmWorker.js missing" >&2; MISSING=1; }
if find "${PKG_DIR}" -mindepth 2 -name package.json -not -path "*/node_modules/*" | grep -q .; then
  echo "post-build: a nested package.json is present under pkg/:" >&2
  find "${PKG_DIR}" -mindepth 2 -name package.json -not -path "*/node_modules/*" >&2
  MISSING=1
fi
[ "${MISSING}" = 0 ] || fail "assembly incomplete."
echo "Assembled ${PKG_DIR}: run 'npm run pack' to produce the tarball."
