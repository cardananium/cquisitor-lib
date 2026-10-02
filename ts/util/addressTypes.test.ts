import { describe, expect, test } from "bun:test";
import { stakeCredentialOf, type DecodedAddress } from "./addressTypes.js";

describe("stakeCredentialOf", () => {
  test("a reward address reports the credential the decoder puts in payment_cred", () => {
    const decoded: DecodedAddress = {
      address_type: "Reward",
      details: { payment_cred: { type: "ScriptHash", credential: "abcd" } },
    };
    expect(stakeCredentialOf(decoded)).toEqual({ type: "ScriptHash", credential: "abcd" });
  });

  test("an address carrying both parts reports the staking half, not the payment half", () => {
    const decoded: DecodedAddress = {
      address_type: "Base",
      details: {
        payment_cred: { type: "ScriptHash", credential: "1111" },
        staking_cred: { type: "KeyHash", credential: "2222" },
      },
    };
    expect(stakeCredentialOf(decoded)).toEqual({ type: "KeyHash", credential: "2222" });
  });

  test("an address with no staking part has no stake credential", () => {
    const enterprise: DecodedAddress = {
      address_type: "Enterprise",
      details: { payment_cred: { type: "KeyHash", credential: "3333" } },
    };
    expect(stakeCredentialOf(enterprise)).toBeNull();
    expect(stakeCredentialOf(null)).toBeNull();
    expect(stakeCredentialOf(undefined)).toBeNull();
  });
});
