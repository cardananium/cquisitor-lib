import { afterEach, describe, expect, test } from "bun:test";
import { BlockfrostClient } from "./blockfrostClient.js";
import { koiosProposalToGovActionContext } from "./transactionValidation.js";

const TX = "c21b00f90f18fce4003edf42b0b0d455126e01c946e80cc5341a9f9750caf795";
const BASE = "https://cardano-mainnet.blockfrost.io/api/v0";

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

/** Serve `routes` (path → JSON body) in place of Blockfrost; anything else is a 404. Returns the paths asked for. */
function serve(routes: Record<string, unknown>): string[] {
  const asked: string[] = [];
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const path = url.startsWith(BASE) ? url.slice(BASE.length) : url;
    asked.push(path);
    if (!(path in routes)) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(routes[path]), { status: 200, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return asked;
}

function proposal(governance_type: string, cert_index: number) {
  return {
    tx_hash: TX,
    cert_index,
    governance_type,
    deposit: "100000000000",
    return_address: "stake1u8ld3x4zxc6ftskes9ryfnme2ta9vhz8d0v2v7mz9ruprqc3xfq9w",
    expiration: 600,
    enacted_epoch: null,
    ratified_epoch: null,
    expired_epoch: null,
    dropped_epoch: null,
  };
}

describe("Blockfrost proposals carry what the validator reads", () => {
  // The validator lets a stake pool vote on a parameter change only when the
  // change touches the security group, which it reads from `changedParameters`.
  test("a ParameterChange carries the parameters it changes", async () => {
    const asked = serve({
      [`/governance/proposals/${TX}/0`]: proposal("parameter_change", 0),
      [`/governance/proposals/${TX}/0/parameters`]: {
        tx_hash: TX,
        cert_index: 0,
        parameters: { epoch: null, min_fee_a: null, max_block_ex_mem: 72000000, max_block_ex_steps: 20000000000, max_tx_ex_mem: 16500000, min_pool_cost: null },
      },
      [`/governance/proposals/${TX}/1`]: proposal("info_action", 1),
    });
    const client = new BlockfrostClient({ network: "mainnet", apiKey: "test" });
    const [change, info] = await client.getProposalsByRefs([
      { txHash: TX, index: 0 },
      { txHash: TX, index: 1 },
    ]);
    expect(koiosProposalToGovActionContext(change).changedParameters).toEqual(["max_block_ex_mem", "max_block_ex_steps", "max_tx_ex_mem"]);
    // Only a ParameterChange has parameters to fetch.
    expect(asked).not.toContain(`/governance/proposals/${TX}/1/parameters`);
    expect("changedParameters" in koiosProposalToGovActionContext(info)).toBe(false);
  });

  test("a ParameterChange whose parameters are not served claims none", async () => {
    serve({ [`/governance/proposals/${TX}/0`]: proposal("parameter_change", 0) });
    const client = new BlockfrostClient({ network: "mainnet", apiKey: "test" });
    const [change] = await client.getProposalsByRefs([{ txHash: TX, index: 0 }]);
    expect(change.proposal_type).toBe("ParameterChange");
    expect("changedParameters" in koiosProposalToGovActionContext(change)).toBe(false);
  });
});
