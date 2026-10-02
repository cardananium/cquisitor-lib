// The Conway-era CDDL from IntersectMBO/cardano-ledger, vendored for the tests
// so they run with no network and against a text that cannot change under them:
//
//   eras/conway/impl/cddl/data/conway.cddl
//   at commit fb4164955c9dd1c4af03611af2cc73de92e2f00d
//
// Copyright 2018-2023 Input Output Global Inc (IOG), licensed under the Apache
// License 2.0 <http://www.apache.org/licenses/LICENSE-2.0>. conway.cddl next to
// this file is a verbatim copy, its generated-file header included.
//
// Test support only: ts/testSupport is excluded from the pkg/lib build.

import { readFileSync } from "node:fs";

export const CONWAY_CDDL: string = readFileSync(new URL("./conway.cddl", import.meta.url), "utf8");
