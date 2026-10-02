import { describe, expect, test } from "bun:test";
import type { KoiosProposal } from "./koiosTypes.js";
import { changedParametersOf, koiosProposalToGovActionContext } from "./transactionValidation.js";

// A Koios `proposal_list` row, trimmed to the fields the conversion reads.
function proposal(over: Partial<KoiosProposal>): KoiosProposal {
  return {
    proposal_tx_hash: "c21b00f90f18fce4003edf42b0b0d455126e01c946e80cc5341a9f9750caf795",
    proposal_index: 0,
    proposal_type: "ParameterChange",
    expired_epoch: null,
    dropped_epoch: null,
    param_proposal: null,
    ...over,
  } as KoiosProposal;
}

describe("the parameters a ParameterChange changes reach the validation context", () => {
  // The validator allows a stake pool's vote on a parameter change only when
  // the change touches the security group; it reads that from
  // `changedParameters`, so the chain pipeline must fill it from Koios.
  test("a ParameterChange carries the names of its non-null param_proposal fields", () => {
    const row = proposal({
      param_proposal: { max_tx_ex_mem: 16500000, max_tx_ex_steps: 10000000000, max_block_ex_mem: 72000000, max_block_ex_steps: 20000000000, min_pool_cost: null },
    });
    const context = koiosProposalToGovActionContext(row);
    expect(context.actionType).toBe("parameterChangeAction");
    expect(context.changedParameters).toEqual(["max_tx_ex_mem", "max_tx_ex_steps", "max_block_ex_mem", "max_block_ex_steps"]);
    expect(context.actionId.index).toBe(0);
    expect(context.isActive).toBe(true);
  });

  test("a param_proposal written as JSON text is read the same way", () => {
    expect(changedParametersOf(proposal({ param_proposal: '{"max_block_size": 90112}' }))).toEqual(["max_block_size"]);
  });

  test("nothing is claimed when the row names no parameters or is another action", () => {
    for (const param_proposal of [null, undefined, "not json", [1, 2], 5]) {
      expect(changedParametersOf(proposal({ param_proposal }))).toBeUndefined();
      expect("changedParameters" in koiosProposalToGovActionContext(proposal({ param_proposal }))).toBe(false);
    }
    const info = koiosProposalToGovActionContext(proposal({ proposal_type: "InfoAction", param_proposal: { max_tx_size: 1 } }));
    expect(info.actionType).toBe("infoAction");
    expect("changedParameters" in info).toBe(false);
  });
});
