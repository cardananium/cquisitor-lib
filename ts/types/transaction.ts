// Decoded-transaction model: the JSON shape cquisitor-lib's Transaction decoder
// emits (CSL-style field names), plus the small application-level types that
// travel with it (network, diagnostics, UTxO info map). UI component props stay
// in the app.

import type { ExtractedHashes, NetworkType } from "@cardananium/cquisitor-lib/wasm";
import type { KoiosUtxoInfo } from "../chain/koiosTypes.js";

// Re-export for convenience
export type { ExtractedHashes };
export type { KoiosUtxoInfo };

/** The network a decoded transaction is looked at on: the library's `NetworkType`. */
export type CardanoNetwork = NetworkType;

/**
 * Map of UTxO reference (txHash#outputIndex) to KoiosUtxoInfo
 */
export type InputUtxoInfoMap = Map<string, KoiosUtxoInfo>;

// --- Native Script Types ---

export interface ScriptPubkey {
  addr_keyhash: string;
}

export interface ScriptAll {
  native_scripts: NativeScript[];
}

export interface ScriptAny {
  native_scripts: NativeScript[];
}

export interface ScriptNOfK {
  /**
   * The required count, any int64 as the ledger reads it (zero or below
   * always holds): a `number`, or a `bigint` past 2^53.
   */
  n: number | bigint;
  native_scripts: NativeScript[];
}

export interface TimelockStart {
  slot: string;
}

export interface TimelockExpiry {
  slot: string;
}

export type NativeScript =
  | { ScriptPubkey: ScriptPubkey }
  | { ScriptAll: ScriptAll }
  | { ScriptAny: ScriptAny }
  | { ScriptNOfK: ScriptNOfK }
  | { TimelockStart: TimelockStart }
  | { TimelockExpiry: TimelockExpiry };

// --- Plutus Scripts ---

/** The Plutus language a script is written for. */
export type PlutusLanguage = "PlutusV1" | "PlutusV2" | "PlutusV3";

/**
 * A Plutus script as the decoder answers it, wherever a transaction holds one
 * (witness set, auxiliary data, an output's script reference): the compiled
 * script as hex, without the CBOR bytes header around it, and its language
 * (taken from the key or script-reference tag that carries it).
 */
export interface PlutusScript {
  bytes: string;
  language: PlutusLanguage;
}

// --- Auxiliary Data ---

export interface AuxiliaryData {
  metadata?: { [k: string]: string } | null;
  native_scripts?: NativeScript[] | null;
  /** Plutus V1, V2 and V3 scripts (keys 2, 3 and 4 of tag-259 auxiliary data); `language` tells them apart. */
  plutus_scripts?: PlutusScript[] | null;
  prefer_alonzo_format: boolean;
}

// --- Credential Types ---

export type CredType =
  | { Script: string }
  | { Key: string };

// --- Certificate Types ---

export interface StakeRegistration {
  coin?: string | null;
  stake_credential: CredType;
}

export interface StakeDeregistration {
  coin?: string | null;
  stake_credential: CredType;
}

export interface StakeDelegation {
  pool_keyhash: string;
  stake_credential: CredType;
}

export interface PoolRegistration {
  pool_params: PoolParams;
}

export interface PoolParams {
  cost: string;
  margin: UnitInterval;
  operator: string;
  pledge: string;
  pool_metadata?: PoolMetadata | null;
  pool_owners: string[];
  relays: Relay[];
  reward_account: string;
  vrf_keyhash: string;
}

export interface UnitInterval {
  denominator: string;
  numerator: string;
}

export interface PoolMetadata {
  pool_metadata_hash: string;
  url: string;
}

export type Relay =
  | { SingleHostAddr: SingleHostAddr }
  | { SingleHostName: SingleHostName }
  | { MultiHostName: MultiHostName };

export interface SingleHostAddr {
  ipv4?: [number, number, number, number] | null;
  ipv6?: number[] | null;
  port?: number | null;
}

export interface SingleHostName {
  dns_name: string;
  port?: number | null;
}

export interface MultiHostName {
  dns_name: string;
}

export interface PoolRetirement {
  epoch: number;
  pool_keyhash: string;
}

export interface GenesisKeyDelegation {
  genesis_delegate_hash: string;
  genesishash: string;
  vrf_keyhash: string;
}

export interface MoveInstantaneousRewardsCert {
  move_instantaneous_reward: MoveInstantaneousReward;
}

export interface MoveInstantaneousReward {
  pot: "Reserves" | "Treasury";
  variant: MIREnum;
}

export type MIREnum =
  | { ToOtherPot: string }
  | { ToStakeCredentials: StakeToCoin[] };

export interface StakeToCoin {
  amount: string;
  stake_cred: CredType;
}

export interface Anchor {
  anchor_data_hash: string;
  anchor_url: string;
}

export interface CommitteeHotAuth {
  committee_cold_credential: CredType;
  committee_hot_credential: CredType;
}

export interface CommitteeColdResign {
  anchor?: Anchor | null;
  committee_cold_credential: CredType;
}

export interface DRepDeregistration {
  coin: string;
  voting_credential: CredType;
}

export interface DRepRegistration {
  anchor?: Anchor | null;
  coin: string;
  voting_credential: CredType;
}

export interface DRepUpdate {
  anchor?: Anchor | null;
  voting_credential: CredType;
}

export type DRep =
  | "AlwaysAbstain"
  | "AlwaysNoConfidence"
  | { KeyHash: string }
  | { ScriptHash: string };

export interface StakeAndVoteDelegation {
  drep: DRep;
  pool_keyhash: string;
  stake_credential: CredType;
}

export interface StakeRegistrationAndDelegation {
  coin: string;
  pool_keyhash: string;
  stake_credential: CredType;
}

export interface StakeVoteRegistrationAndDelegation {
  coin: string;
  drep: DRep;
  pool_keyhash: string;
  stake_credential: CredType;
}

export interface VoteDelegation {
  drep: DRep;
  stake_credential: CredType;
}

export interface VoteRegistrationAndDelegation {
  coin: string;
  drep: DRep;
  stake_credential: CredType;
}

export type Certificate =
  | { StakeRegistration: StakeRegistration }
  | { StakeDeregistration: StakeDeregistration }
  | { StakeDelegation: StakeDelegation }
  | { PoolRegistration: PoolRegistration }
  | { PoolRetirement: PoolRetirement }
  | { GenesisKeyDelegation: GenesisKeyDelegation }
  | { MoveInstantaneousRewardsCert: MoveInstantaneousRewardsCert }
  | { CommitteeHotAuth: CommitteeHotAuth }
  | { CommitteeColdResign: CommitteeColdResign }
  | { DRepDeregistration: DRepDeregistration }
  | { DRepRegistration: DRepRegistration }
  | { DRepUpdate: DRepUpdate }
  | { StakeAndVoteDelegation: StakeAndVoteDelegation }
  | { StakeRegistrationAndDelegation: StakeRegistrationAndDelegation }
  | { StakeVoteRegistrationAndDelegation: StakeVoteRegistrationAndDelegation }
  | { VoteDelegation: VoteDelegation }
  | { VoteRegistrationAndDelegation: VoteRegistrationAndDelegation };

// --- Governance Types ---

/** A voter as the decoded transaction JSON carries it (not the validator's `Voter`). */
export type TxVoter =
  | { ConstitutionalCommitteeHotCred: CredType }
  | { DRep: CredType }
  | { StakingPool: string };

export type VoteKind = "No" | "Yes" | "Abstain";

/** A governance action id as the decoded transaction JSON carries it (not the validator's `GovernanceActionId`). */
export interface TxGovernanceActionId {
  index: number;
  transaction_id: string;
}

export interface VotingProcedure {
  anchor?: Anchor | null;
  vote: VoteKind;
}

export interface Vote {
  action_id: TxGovernanceActionId;
  voting_procedure: VotingProcedure;
}

export interface VoterVotes {
  voter: TxVoter;
  votes: Vote[];
}

/** A protocol version as the decoded transaction JSON carries it (not the validator's `ProtocolVersion`). */
export interface TxProtocolVersion {
  major: number;
  minor: number;
}

export interface ProtocolParamUpdate {
  ada_per_utxo_byte?: string | null;
  collateral_percentage?: number | null;
  // ... other protocol params (simplified)
  [key: string]: unknown;
}

/** A pre-Conway protocol-parameter update proposal (by genesis-key delegates), as the decoded transaction JSON carries it. */
export interface TxUpdate {
  /** Genesis key hash (hex) to the parameters it proposes. */
  proposed_protocol_parameter_updates: Record<string, ProtocolParamUpdate>;
  /** The epoch the proposal is for. */
  epoch: number;
}

export interface ParameterChangeAction {
  gov_action_id?: TxGovernanceActionId | null;
  policy_hash?: string | null;
  protocol_param_updates: ProtocolParamUpdate;
}

export interface HardForkInitiationAction {
  gov_action_id?: TxGovernanceActionId | null;
  protocol_version: TxProtocolVersion;
}

export interface TreasuryWithdrawalsAction {
  policy_hash?: string | null;
  withdrawals: { [k: string]: string };
}

export interface NoConfidenceAction {
  gov_action_id?: TxGovernanceActionId | null;
}

export interface Committee {
  members: CommitteeMember[];
  quorum_threshold: UnitInterval;
}

export interface CommitteeMember {
  stake_credential: CredType;
  term_limit: number;
}

export interface UpdateCommitteeAction {
  committee: Committee;
  gov_action_id?: TxGovernanceActionId | null;
  members_to_remove: CredType[];
}

export interface Constitution {
  anchor: Anchor;
  script_hash?: string | null;
}

export interface NewConstitutionAction {
  constitution: Constitution;
  gov_action_id?: TxGovernanceActionId | null;
}

export type InfoAction = [];

export type GovernanceAction =
  | { ParameterChangeAction: ParameterChangeAction }
  | { HardForkInitiationAction: HardForkInitiationAction }
  | { TreasuryWithdrawalsAction: TreasuryWithdrawalsAction }
  | { NoConfidenceAction: NoConfidenceAction }
  | { UpdateCommitteeAction: UpdateCommitteeAction }
  | { NewConstitutionAction: NewConstitutionAction }
  | { InfoAction: InfoAction };

export interface VotingProposal {
  anchor: Anchor;
  deposit: string;
  governance_action: GovernanceAction;
  reward_account: string;
}

// --- Data and Script References ---

export type DataOption =
  | { DataHash: string }
  | { Data: string };

export type ScriptRef =
  | { NativeScript: NativeScript }
  | { PlutusScript: PlutusScript };

// --- Bootstrap Witness ---

export interface BootstrapWitness {
  attributes: number[];
  chain_code: number[];
  signature: string;
  vkey: string;
}

// ============================================
// Application-specific Types
// ============================================

// Re-use ValidationDiagnostic from ValidationJsonViewer
export interface ValidationDiagnostic {
  severity: "error" | "warning";
  message: string;
  hint?: string | null;
  locations?: string[];
  phase?: string;
  errorType?: string;
  errorData?: Record<string, unknown>;
}

// Transaction types
export interface TransactionData {
  auxiliary_data?: AuxiliaryData | null;
  body: TransactionBody;
  is_valid: boolean;
  witness_set: WitnessSet;
}

/**
 * What `decode(hex, "Transaction")` answers: the transaction id next to the
 * decoded transaction (read the body as `decoded.transaction.body`).
 */
export interface DecodedTransaction {
  /** Blake2b-256 of the body bytes exactly as the transaction carries them, hex. */
  transaction_hash: string;
  transaction: TransactionData;
}

export interface TransactionBody {
  inputs: TransactionInput[];
  outputs: TransactionOutput[];
  fee: string;
  ttl?: string | null;
  certs?: Certificate[] | null;
  withdrawals?: Record<string, string> | null;
  /** A pre-Conway protocol-parameter update proposal; the decoder answers `null` when there is none (always, in Conway). */
  update?: TxUpdate | null;
  mint?: [string, Record<string, string>][] | null;
  auxiliary_data_hash?: string | null;
  validity_start_interval?: string | null;
  script_data_hash?: string | null;
  collateral?: TransactionInput[] | null;
  required_signers?: string[] | null;
  network_id?: string | null;
  collateral_return?: TransactionOutput | null;
  total_collateral?: string | null;
  reference_inputs?: TransactionInput[] | null;
  voting_procedures?: VoterVotes[] | null;
  voting_proposals?: VotingProposal[] | null;
  current_treasury_value?: string | null;
  donation?: string | null;
}

export interface TransactionInput {
  transaction_id: string;
  index: number;
}

export interface TransactionOutput {
  address: string;
  amount: {
    coin: string;
    multiasset?: Record<string, Record<string, string>> | null;
  };
  plutus_data?: DataOption | null;
  script_ref?: ScriptRef | null;
}

export interface WitnessSet {
  vkeys?: VkeyWitness[] | null;
  native_scripts?: NativeScript[] | null;
  bootstraps?: BootstrapWitness[] | null;
  /** Plutus V1, V2 and V3 scripts (witness keys 3, 6 and 7); `language` tells them apart. */
  plutus_scripts?: PlutusScript[] | null;
  plutus_data?: { elems: string[]; definite_encoding?: boolean | null } | null;
  redeemers?: Redeemer[] | null;
}

export interface VkeyWitness {
  vkey: string;
  vkey_hash?: string;
  signature: string;
}

export interface Redeemer {
  tag: string;
  index: string;
  data: string;
  ex_units: { mem: string; steps: string };
}
