/**
 * Online validation pipeline: what a transaction needs (`necessaryData`),
 * fetched from Koios or Blockfrost into a `ValidationInputContext`, then
 * `validateTransaction`. Every library call goes through the typed API, so it
 * runs on whatever backend the host configured.
 */

import type {
  NecessaryInputData,
  ValidationInputContext,
  ValidationResult,
  ProtocolParameters,
  UtxoInputContext,
  AccountInputContext,
  DrepInputContext,
  PoolInputContext,
  GovActionInputContext,
  CommitteeInputContext,
  ConstitutionContext,
  UTxO,
  TxInput,
  TxOutput,
  Asset,
  LocalCredential,
  GovernanceActionId,
  GovernanceActionType,
  CostModels,
  ExUnits,
  SubCoin,
  ExUnitPrices,
  NetworkType,
} from '@cardananium/cquisitor-lib/wasm';

import { getLogger } from '../configure.js';
import { necessaryData, refScriptBytes, validateTransaction } from '../api/transaction.js';
import { hexToBytes } from '../util/hex.js';
import { KoiosClient, formatUtxoRef, govActionTypeToKoiosProposalType } from './koiosClient.js';
import { BlockfrostClient } from './blockfrostClient.js';
import type { GovActionRef, BlockchainDataClient } from './koiosClient.js';
import { ensurePoolIdBech32 } from './cip129.js';
import { formatScriptRefForLib, encodeCborBytes } from './scriptRefFormat.js';
import type {
  KoiosNetworkType,
  KoiosUtxoInfo,
  KoiosAccountInfo,
  KoiosDrepInfo,
  KoiosCommitteeMember,
  KoiosProposal,
  KoiosEpochParams,
} from './koiosTypes.js';

// Re-export types for external use
export type { NecessaryInputData, ValidationInputContext, ValidationResult, NetworkType };
export type { KoiosUtxoInfo } from './koiosTypes.js';

/**
 * Which blockchain data provider to use for fetching the validation context.
 * Both providers expose the same surface — see BlockchainDataClient — so the
 * downstream pipeline doesn't care which one is in play.
 */
export type DataProvider = 'koios' | 'blockfrost';

/**
 * Configuration for transaction validation
 */
export interface TransactionValidationConfig {
  txHex: string;
  network: NetworkType;
  /** Defaults to 'koios' for backwards compatibility. */
  provider?: DataProvider;
  apiKey?: string;
}

function makeClient(
  provider: DataProvider,
  network: NetworkType,
  apiKey?: string
): BlockchainDataClient {
  if (provider === 'blockfrost') {
    if (!apiKey) throw new Error('Blockfrost project_id is required');
    return new BlockfrostClient({ network, apiKey });
  }
  return new KoiosClient({ network, apiKey });
}

/**
 * Fetch a transaction's raw CBOR (hex) by its hash from the chosen provider
 * (Koios `tx_cbor` / Blockfrost `/txs/{hash}/cbor`). Throws if not found.
 */
export async function fetchTxCbor(
  txHash: string,
  opts: { provider: DataProvider; network: NetworkType; apiKey?: string }
): Promise<string> {
  const hash = txHash.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) {
    throw new Error("Enter a 64-character hex transaction hash");
  }
  const client = makeClient(opts.provider, opts.network, opts.apiKey);
  const res = await client.getTxCbor([hash]);
  const cbor = res[0]?.cbor;
  if (!cbor) throw new Error("Transaction not found on this network/provider");
  return cbor;
}

/**
 * Result of fetching necessary data from Koios
 */
export interface FetchedValidationData {
  utxoSet: UtxoInputContext[];
  accountContexts: AccountInputContext[];
  poolContexts: PoolInputContext[];
  drepContexts: DrepInputContext[];
  govActionContexts: GovActionInputContext[];
  lastEnactedGovAction: GovActionInputContext[];
  currentCommitteeMembers: CommitteeInputContext[];
  potentialCommitteeMembers: CommitteeInputContext[];
  constitution: ConstitutionContext;
  protocolParameters: ProtocolParameters;
  slot: bigint;
  treasuryValue: bigint;
  /** Raw Koios UTxO info for display purposes */
  utxoInfos: KoiosUtxoInfo[];
}

/**
 * Extended validation result that includes both the validation result and the fetched UTxO info
 */
export interface ExtendedValidationResult {
  result: ValidationResult;
  /** Map of UTxO references (txHash#outputIndex) to KoiosUtxoInfo */
  utxoInfoMap: Map<string, KoiosUtxoInfo>;
  /** Full fetched context (useful for sharing the validated state via URL) */
  fetchedContext: FetchedValidationData;
}

/**
 * Maps cquisitor-lib NetworkType to Koios network
 */
function mapToKoiosNetwork(network: NetworkType): KoiosNetworkType {
  return network;
}

export interface SubmitTransactionConfig {
  txHex: string;
  network: NetworkType;
  provider: DataProvider;
  apiKey: string;
}

export async function submitTransaction(
  config: SubmitTransactionConfig
): Promise<string> {
  const client = makeClient(config.provider, mapToKoiosNetwork(config.network), config.apiKey);
  return client.submitTransaction(config.txHex);
}

// ============================================================================
// UTxO Conversion Functions
// ============================================================================

/**
 * Converts Koios UTxO info to cquisitor-lib UTxO format
 * @param koiosUtxo - The Koios UTxO info
 * @param scriptRefBytesOverride - Optional override for reference script bytes (extracted from tx CBOR)
 */
function koiosUtxoToLibUtxo(koiosUtxo: KoiosUtxoInfo, scriptRefBytesOverride?: string): UTxO {
  const input: TxInput = {
    txHash: koiosUtxo.tx_hash,
    outputIndex: koiosUtxo.tx_index,
  };

  // Build asset array
  const assets: Asset[] = [
    { unit: 'lovelace', quantity: koiosUtxo.value },
  ];

  if (koiosUtxo.asset_list) {
    for (const asset of koiosUtxo.asset_list) {
      assets.push({
        unit: asset.policy_id + asset.asset_name,
        quantity: asset.quantity,
      });
    }
  }

  // Determine scriptRef bytes:
  // - scriptRefBytesOverride (from get_ref_script_bytes): already properly formatted, use as-is
  // - koiosUtxo.reference_script?.bytes (from Koios API): raw script bytes, need formatting
  let scriptRef: string | undefined;
  
  if (scriptRefBytesOverride) {
    // Already formatted from get_ref_script_bytes, pass through formatScriptRefForLib
    // (it will detect it's already formatted and return as-is)
    scriptRef = formatScriptRefForLib(scriptRefBytesOverride, koiosUtxo.reference_script?.type);
  } else if (koiosUtxo.reference_script?.bytes) {
    // Koios returns raw script bytes
    // For Plutus scripts: first wrap in CBOR bytes, then format as ScriptRef
    // For Native scripts: pass directly to formatScriptRefForLib
    const scriptType = koiosUtxo.reference_script.type?.toLowerCase() ?? '';
    const isPlutus = scriptType.startsWith('plutus');
    
    const scriptBytes = isPlutus 
      ? encodeCborBytes(koiosUtxo.reference_script.bytes)
      : koiosUtxo.reference_script.bytes;
    
    scriptRef = formatScriptRefForLib(scriptBytes, koiosUtxo.reference_script.type);
  }

  const output: TxOutput = {
    address: koiosUtxo.address,
    amount: assets,
    dataHash: koiosUtxo.datum_hash ?? undefined,
    plutusData: koiosUtxo.inline_datum?.bytes ?? undefined,
    scriptRef,
    scriptHash: koiosUtxo.reference_script?.hash ?? undefined,
  };

  return { input, output };
}

/**
 * Converts Koios UTxO info to UtxoInputContext
 * @param koiosUtxo - The Koios UTxO info
 * @param scriptRefBytesOverride - Optional override for reference script bytes
 */
function koiosUtxoToUtxoContext(koiosUtxo: KoiosUtxoInfo, scriptRefBytesOverride?: string): UtxoInputContext {
  return {
    utxo: koiosUtxoToLibUtxo(koiosUtxo, scriptRefBytesOverride),
    isSpent: koiosUtxo.is_spent,
  };
}

/**
 * Identifies UTxOs that have reference scripts but missing bytes
 */
function findUtxosWithMissingRefScriptBytes(utxoInfos: KoiosUtxoInfo[]): KoiosUtxoInfo[] {
  return utxoInfos.filter(
    utxo => utxo.reference_script && !utxo.reference_script.bytes
  );
}

/**
 * Extracts reference script bytes from transaction CBOR for UTxOs with missing bytes
 * @param utxosWithMissingBytes - UTxOs that need reference script bytes extracted
 * @param client - Koios client for fetching tx CBOR
 * @returns Map of "txHash#outputIndex" to extracted script bytes
 */
async function extractMissingRefScriptBytes(
  utxosWithMissingBytes: KoiosUtxoInfo[],
  client: BlockchainDataClient
): Promise<Map<string, string>> {
  const result = new Map<string, string>();
  
  if (utxosWithMissingBytes.length === 0) {
    return result;
  }

  // Group UTxOs by transaction hash to minimize API calls
  const utxosByTxHash = new Map<string, KoiosUtxoInfo[]>();
  for (const utxo of utxosWithMissingBytes) {
    const existing = utxosByTxHash.get(utxo.tx_hash) || [];
    existing.push(utxo);
    utxosByTxHash.set(utxo.tx_hash, existing);
  }

  // Fetch transaction CBORs
  const txHashes = Array.from(utxosByTxHash.keys());
  const txCborResponses = await client.getTxCbor(txHashes);
  
  // Create a map for quick lookup
  const txCborMap = new Map<string, string>();
  for (const response of txCborResponses) {
    txCborMap.set(response.tx_hash, response.cbor);
  }

  // Extract reference script bytes for each UTxO
  for (const [txHash, utxos] of utxosByTxHash.entries()) {
    const txCbor = txCborMap.get(txHash);
    if (!txCbor) {
      getLogger().warn(`Could not fetch CBOR for transaction ${txHash}`);
      continue;
    }

    for (const utxo of utxos) {
      try {
        const scriptBytes = await refScriptBytes(txCbor, utxo.tx_index);
        const key = `${utxo.tx_hash}#${utxo.tx_index}`;
        result.set(key, scriptBytes);
      } catch (error) {
        getLogger().warn(`Failed to extract ref script bytes for ${utxo.tx_hash}#${utxo.tx_index}:`, error);
      }
    }
  }

  return result;
}

/**
 * Converts Koios account info to AccountInputContext
 * @param account - Koios account info
 * @param originalAddress - Original address from transaction (Koios may normalize it)
 */
function koiosAccountToAccountContext(
  account: KoiosAccountInfo, 
  originalAddress: string
): AccountInputContext {
  return {
    bech32Address: originalAddress, // Use original address, not Koios-normalized
    isRegistered: account.status === 'registered',
    payedDeposit: account.deposit ? parseInt(account.deposit, 10) : null,
    delegatedToDrep: account.delegated_drep ?? null,
    delegatedToPool: account.delegated_pool ?? null,
    balance: account.rewards_available ? parseInt(account.rewards_available, 10) : null,
  };
}

/**
 * Converts Koios DRep info to DrepInputContext
 */
function koiosDrepToDrepContext(drep: KoiosDrepInfo): DrepInputContext {
  return {
    bech32Drep: drep.drep_id,
    isRegistered: drep.drep_status === 'registered',
    payedDeposit: drep.deposit ? parseInt(drep.deposit, 10) : null,
  };
}

/**
 * Maps proposal type to governance action type
 */
function mapProposalTypeToActionType(proposalType: string): GovernanceActionType {
  const mapping: Record<string, GovernanceActionType> = {
    'ParameterChange': 'parameterChangeAction',
    'HardForkInitiation': 'hardForkInitiationAction',
    'TreasuryWithdrawals': 'treasuryWithdrawalsAction',
    'NoConfidence': 'noConfidenceAction',
    'NewCommittee': 'updateCommitteeAction',
    'NewConstitution': 'newConstitutionAction',
    'InfoAction': 'infoAction',
  };
  return mapping[proposalType] ?? 'infoAction';
}

/**
 * The protocol parameters a ParameterChange proposal changes: the names of the
 * non-null fields of Koios' `param_proposal` (db-sync column names such as
 * `max_block_ex_mem`, which the validator accepts). `undefined` for any other
 * action, or when the row names no parameters: the validator then treats the
 * change as not touching the security group.
 */
export function changedParametersOf(proposal: Pick<KoiosProposal, 'proposal_type' | 'param_proposal'>): string[] | undefined {
  if (proposal.proposal_type !== 'ParameterChange') return undefined;
  let params = proposal.param_proposal;
  if (typeof params === 'string') {
    try {
      params = JSON.parse(params);
    } catch {
      return undefined;
    }
  }
  if (params === null || typeof params !== 'object' || Array.isArray(params)) return undefined;
  return Object.entries(params as Record<string, unknown>)
    .filter(([, value]) => value !== null && value !== undefined)
    .map(([name]) => name);
}

/**
 * Converts Koios proposal to GovActionInputContext. A ParameterChange carries
 * `changedParameters`, which decides whether a stake pool may vote on it.
 */
export function koiosProposalToGovActionContext(proposal: KoiosProposal): GovActionInputContext {
  // Parse tx_hash from proposal_id or proposal_tx_hash
  const txHashBytes = hexToBytes(proposal.proposal_tx_hash);

  const actionId: GovernanceActionId = {
    txHash: Array.from(txHashBytes),
    index: proposal.proposal_index,
  };

  const changedParameters = changedParametersOf(proposal);
  return {
    actionId,
    actionType: mapProposalTypeToActionType(proposal.proposal_type),
    isActive: proposal.expired_epoch === null && proposal.dropped_epoch === null,
    ...(changedParameters ? { changedParameters } : {}),
  };
}

/**
 * Converts hex credential to LocalCredential
 */
function hexToLocalCredential(hex: string, hasScript: boolean): LocalCredential {
  const bytes = Array.from(hexToBytes(hex));
  if (hasScript) {
    return { scriptHash: bytes };
  }
  return { keyHash: bytes };
}

/**
 * Converts Koios committee member to CommitteeInputContext
 */
function koiosCommitteeToCommitteeContext(member: KoiosCommitteeMember): CommitteeInputContext {
  const coldCredential = hexToLocalCredential(member.cc_cold_hex, member.cc_cold_has_script);
  
  let hotCredential: LocalCredential | null = null;
  if (member.cc_hot_hex && member.cc_hot_has_script !== null) {
    hotCredential = hexToLocalCredential(member.cc_hot_hex, member.cc_hot_has_script);
  }

  return {
    committeeMemberCold: coldCredential,
    committeeMemberHot: hotCredential,
    isResigned: member.status === 'resigned',
  };
}


/**
 * Converts Koios epoch params to ProtocolParameters
 */
function koiosParamsToProtocolParams(params: KoiosEpochParams): ProtocolParameters {
  // Build cost models
  const costModels: CostModels = {};
  if (params.cost_models?.PlutusV1) {
    costModels.plutusV1 = params.cost_models.PlutusV1;
  }
  if (params.cost_models?.PlutusV2) {
    costModels.plutusV2 = params.cost_models.PlutusV2;
  }
  if (params.cost_models?.PlutusV3) {
    costModels.plutusV3 = params.cost_models.PlutusV3;
  }

  // Execution prices - convert from decimal to rational
  const memPrice: SubCoin = priceToSubCoin(params.price_mem ?? 0);
  const stepPrice: SubCoin = priceToSubCoin(params.price_step ?? 0);

  const executionPrices: ExUnitPrices = {
    memPrice,
    stepPrice,
  };

  // Max execution units
  const maxTxExecutionUnits: ExUnits = {
    mem: BigInt(params.max_tx_ex_mem ?? 0),
    steps: BigInt(params.max_tx_ex_steps ?? 0),
  };

  const maxBlockExecutionUnits: ExUnits = {
    mem: BigInt(params.max_block_ex_mem ?? 0),
    steps: BigInt(params.max_block_ex_steps ?? 0),
  };

  // Reference script cost per byte
  const referenceScriptCostPerByte: SubCoin = {
    numerator: BigInt(params.min_fee_ref_script_cost_per_byte ?? 15),
    denominator: BigInt(1),
  };

  return {
    minFeeCoefficientA: BigInt(params.min_fee_a ?? 44),
    minFeeConstantB: BigInt(params.min_fee_b ?? 155381),
    maxBlockBodySize: params.max_block_size ?? 90112,
    maxTransactionSize: params.max_tx_size ?? 16384,
    maxBlockHeaderSize: params.max_bh_size ?? 1100,
    stakeKeyDeposit: BigInt(params.key_deposit ?? '2000000'),
    stakePoolDeposit: BigInt(params.pool_deposit ?? '500000000'),
    maxEpochForPoolRetirement: params.max_epoch ?? 18,
    protocolVersion: [params.protocol_major ?? 9, params.protocol_minor ?? 0],
    minPoolCost: BigInt(params.min_pool_cost ?? '340000000'),
    adaPerUtxoByte: BigInt(params.coins_per_utxo_size ?? '4310'),
    costModels,
    executionPrices,
    maxTxExecutionUnits,
    maxBlockExecutionUnits,
    maxValueSize: params.max_val_size ?? 5000,
    collateralPercentage: params.collateral_percent ?? 150,
    maxCollateralInputs: params.max_collateral_inputs ?? 3,
    governanceActionDeposit: BigInt(params.gov_action_deposit ?? '100000000000'),
    drepDeposit: BigInt(params.drep_deposit ?? '500000000'),
    referenceScriptCostPerByte,
  };
}

/**
 * Converts a decimal price to SubCoin (rational number)
 */
function priceToSubCoin(price: number): SubCoin {
  // Convert to a rational approximation
  // Using 10^10 as denominator for sufficient precision
  const denominator = BigInt(10000000000);
  const numerator = BigInt(Math.round(price * Number(denominator)));
  
  // Simplify the fraction if possible
  const gcd = (a: bigint, b: bigint): bigint => (b === BigInt(0) ? a : gcd(b, a % b));
  const divisor = gcd(numerator, denominator);
  
  return {
    numerator: numerator / divisor,
    denominator: denominator / divisor,
  };
}

/**
 * Helper function to convert byte array to hex string
 */
function bytesToHex(bytes: number[]): string {
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Finds last enacted governance actions for specific types
 */
function findLastEnactedGovActions(
  actionTypes: GovernanceActionType[],
  proposals: KoiosProposal[]
): GovActionInputContext[] {
  const result: GovActionInputContext[] = [];
  
  for (const actionType of actionTypes) {
    // Find the most recent enacted proposal of this type
    const matchingProposals = proposals
      .filter(p => {
        const proposalActionType = mapProposalTypeToActionType(p.proposal_type);
        return proposalActionType === actionType && p.enacted_epoch !== null;
      })
      .sort((a, b) => (b.enacted_epoch ?? 0) - (a.enacted_epoch ?? 0));

    if (matchingProposals.length > 0) {
      result.push(koiosProposalToGovActionContext(matchingProposals[0]));
    }
  }

  return result;
}

/**
 * Converts GovernanceActionId (with txHash as number[]) to GovActionRef (with txHash as hex string)
 */
function govActionIdToRef(actionId: GovernanceActionId): GovActionRef {
  return {
    txHash: bytesToHex(actionId.txHash),
    index: Number(actionId.index),
  };
}

/**
 * Fetches all necessary data from the chosen data provider for transaction validation.
 * `client` lets a host supply its own BlockchainDataClient (caching, retries, request
 * scoping); by default one is created from `provider`/`network`/`apiKey`.
 */
export async function fetchValidationData(
  required: NecessaryInputData,
  network: NetworkType,
  apiKey?: string,
  provider: DataProvider = 'koios',
  client: BlockchainDataClient = makeClient(provider, mapToKoiosNetwork(network), apiKey)
): Promise<FetchedValidationData> {

  // Convert govActions to refs for targeted querying
  const govActionRefs: GovActionRef[] = required.govActions.map(govActionIdToRef);
  
  // Convert lastEnactedGovAction types to Koios proposal types for targeted querying
  const lastEnactedProposalTypes: string[] = required.lastEnactedGovAction.map(
    actionType => govActionTypeToKoiosProposalType(actionType)
  );

  // Fetch all required data in parallel where possible
  // Use targeted queries for proposals instead of fetching all
  const [
    tipResult,
    totalsResult,
    epochParamsResult,
    committeeInfoResult,
    proposalsByRefsResult,
    lastEnactedProposalsResult,
    constitutionResult,
  ] = await Promise.all([
    client.getTip(),
    client.getTotals(),
    client.getEpochParams(),
    client.getCommitteeInfo().catch(() => null), // May fail on older networks
    // Only fetch specific proposals that are referenced in the transaction
    client.getProposalsByRefs(govActionRefs).catch(() => []),
    // Only fetch last enacted proposals for the types needed by the transaction
    client.getLastEnactedProposals(lastEnactedProposalTypes).catch(() => []),
    // Current constitution — supplies the guardrails policy hash that
    // ParameterChange/TreasuryWithdrawals proposals are validated against.
    client.getConstitution().catch(() => null),
  ]);

  // Get current slot and treasury value
  const currentTip = tipResult[0];
  const slot = BigInt(currentTip.abs_slot);
  
  // Get the latest totals (first item is latest epoch)
  const latestTotals = totalsResult[0];
  const treasuryValue = BigInt(latestTotals?.treasury ?? '0');

  // Get latest epoch params
  const latestParams = epochParamsResult[0];
  const protocolParameters = koiosParamsToProtocolParams(latestParams);

  // Fetch UTxO data
  const utxoRefs = required.utxos.map((utxo: TxInput) => 
    formatUtxoRef(utxo.txHash, utxo.outputIndex)
  );
  const utxoInfos = await client.getUtxoInfo(utxoRefs);

  // Find UTxOs with reference scripts but missing bytes
  const utxosWithMissingBytes = findUtxosWithMissingRefScriptBytes(utxoInfos);
  
  // Extract missing reference script bytes from transaction CBORs
  const extractedRefScriptBytes = await extractMissingRefScriptBytes(utxosWithMissingBytes, client);
  
  // Convert UTxOs to UtxoInputContext, using extracted bytes where needed
  const utxoSet = utxoInfos.map(utxo => {
    const key = `${utxo.tx_hash}#${utxo.tx_index}`;
    const extractedBytes = extractedRefScriptBytes.get(key);
    return koiosUtxoToUtxoContext(utxo, extractedBytes);
  });

  // Fetch account data - query one by one to handle Koios address normalization
  const accountContexts: AccountInputContext[] = [];
  for (const account of required.accounts) {
    try {
      const accountInfos = await client.getAccountInfo([account]);
      if (accountInfos.length > 0) {
        // Use original address from transaction, not the one returned by Koios
        accountContexts.push(koiosAccountToAccountContext(accountInfos[0], account));
      } else {
        // Account not found - mark as unregistered
        accountContexts.push({
          bech32Address: account,
          isRegistered: false,
          payedDeposit: null,
          delegatedToDrep: null,
          delegatedToPool: null,
          balance: null,
        });
      }
    } catch (error) {
      getLogger().warn(`Failed to fetch account info for ${account}:`, error);
      // On error, mark as unregistered
      accountContexts.push({
        bech32Address: account,
        isRegistered: false,
        payedDeposit: null,
        delegatedToDrep: null,
        delegatedToPool: null,
        balance: null,
      });
    }
  }

  // Fetch pool data - convert hex pool IDs to bech32 for Koios API
  // The pools field from get_necessary_data_list_js returns hex pool IDs
  // We need to:
  // 1. Convert hex -> bech32 for Koios API request
  // 2. Keep mapping to convert bech32 -> hex for response (since lib expects hex)
  const poolIdMappings: Map<string, string> = new Map(); // bech32 -> original format from lib
  const poolBech32Ids: string[] = [];
  
  for (const poolId of required.pools) {
    try {
      const bech32Id = ensurePoolIdBech32(poolId);
      poolBech32Ids.push(bech32Id);
      poolIdMappings.set(bech32Id, poolId);
    } catch (error) {
      getLogger().warn(`Failed to convert pool ID ${poolId}:`, error);
    }
  }
  
  const poolInfos = await client.getPoolInfo(poolBech32Ids);
  
  // Convert Koios response to PoolInputContext using original format from lib
  const poolContexts: PoolInputContext[] = poolInfos.map(pool => {
    const originalPoolId = poolIdMappings.get(pool.pool_id_bech32) || pool.pool_id_bech32;
    return {
      poolId: originalPoolId,
      isRegistered: pool.pool_status === 'registered',
      retirementEpoch: pool.retiring_epoch ?? null,
    };
  });

  // For pools not found, create unregistered entries with original format
  const foundPoolsBech32 = new Set(poolInfos.map(p => p.pool_id_bech32));
  for (const [bech32Id, originalId] of poolIdMappings.entries()) {
    if (!foundPoolsBech32.has(bech32Id)) {
      poolContexts.push({
        poolId: originalId,
        isRegistered: false,
        retirementEpoch: null,
      });
    }
  }

  // Fetch DRep data
  // Predefined DReps (AlwaysAbstain, AlwaysNoConfidence) are filtered out in koiosClient
  const drepInfos = await client.getDrepInfo(required.dReps);
  const drepContexts = drepInfos.map(koiosDrepToDrepContext);

  // Predefined DReps that should not be queried or added as unregistered
  const PREDEFINED_DREPS = new Set(['AlwaysAbstain', 'AlwaysNoConfidence']);

  // For DReps not found (excluding predefined ones and empty values), create unregistered entries
  const foundDreps = new Set(drepInfos.map(d => d.drep_id));
  for (const drepId of required.dReps) {
    // Skip empty/invalid values
    if (!drepId || drepId.trim() === '') {
      continue;
    }
    // Skip predefined DReps - they are built-in protocol types, not actual registered DReps
    if (PREDEFINED_DREPS.has(drepId)) {
      continue;
    }
    if (!foundDreps.has(drepId)) {
      drepContexts.push({
        bech32Drep: drepId,
        isRegistered: false,
        payedDeposit: null,
      });
    }
  }

  // Process governance actions - proposals are already filtered by refs
  const govActionContexts = proposalsByRefsResult.map(koiosProposalToGovActionContext);

  // Process last enacted governance actions - already filtered by type
  const lastEnactedGovAction = findLastEnactedGovActions(
    required.lastEnactedGovAction,
    lastEnactedProposalsResult
  );

  // Process committee members
  let currentCommitteeMembers: CommitteeInputContext[] = [];
  const potentialCommitteeMembers: CommitteeInputContext[] = [];

  if (committeeInfoResult && committeeInfoResult.members) {
    // All current committee members
    const allCommitteeContexts = committeeInfoResult.members.map(koiosCommitteeToCommitteeContext);
    
    // Filter to find members matching cold credentials
    const coldCredentialSet = new Set(
      required.committeeMembersCold.map((c: LocalCredential) => 
        JSON.stringify('keyHash' in c ? c.keyHash : c.scriptHash)
      )
    );
    
    currentCommitteeMembers = allCommitteeContexts.filter(member => {
      const key = 'keyHash' in member.committeeMemberCold 
        ? member.committeeMemberCold.keyHash 
        : member.committeeMemberCold.scriptHash;
      return coldCredentialSet.has(JSON.stringify(key));
    });

    // Filter to find members matching hot credentials
    const hotCredentialSet = new Set(
      required.committeeMembersHot.map((c: LocalCredential) => 
        JSON.stringify('keyHash' in c ? c.keyHash : c.scriptHash)
      )
    );

    // Find committee members by hot credential
    const membersByHot = allCommitteeContexts.filter(member => {
      if (!member.committeeMemberHot) return false;
      const key = 'keyHash' in member.committeeMemberHot 
        ? member.committeeMemberHot.keyHash 
        : member.committeeMemberHot.scriptHash;
      return hotCredentialSet.has(JSON.stringify(key));
    });

    // Add to current if not already included
    for (const member of membersByHot) {
      const alreadyExists = currentCommitteeMembers.some(
        m => JSON.stringify(m.committeeMemberCold) === JSON.stringify(member.committeeMemberCold)
      );
      if (!alreadyExists) {
        currentCommitteeMembers.push(member);
      }
    }
  }

  // Build the constitution context from the live fetch. Trust the provider's
  // guardrails hash when it supplied a constitution (even if null — that means
  // "no guardrails script"). When there is no result at all (e.g. Blockfrost has
  // no constitution endpoint), leave it null rather than guessing a hash.
  const constitution: ConstitutionContext = {
    guardrailScriptHash: constitutionResult?.guardrailScriptHash ?? null,
  };

  return {
    utxoSet,
    accountContexts,
    poolContexts,
    drepContexts,
    govActionContexts,
    lastEnactedGovAction,
    currentCommitteeMembers,
    potentialCommitteeMembers,
    constitution,
    protocolParameters,
    slot,
    treasuryValue,
    utxoInfos,
  };
}

/**
 * Validate a transaction against live chain state: ask the library what the
 * transaction needs (`necessaryData`), fetch it from Koios or Blockfrost
 * (`fetchValidationData`), build the `ValidationInputContext` and run
 * `validateTransaction`. The fetched context and a UTxO lookup map for
 * display come back alongside the result.
 *
 * @example
 * ```typescript
 * const { result, utxoInfoMap } = await validateTransactionOnline({
 *   txHex: "84a400...",
 *   network: "mainnet",
 *   apiKey: "your-koios-api-key",
 * });
 *
 * if (result.errors.length === 0 && result.phase2_errors.length === 0) {
 *   console.log("Transaction is valid!");
 * } else {
 *   console.log("Validation errors:", result.errors);
 * }
 *
 * const inputInfo = utxoInfoMap.get("txHash#0");
 * ```
 */
export async function validateTransactionOnline(
  config: TransactionValidationConfig
): Promise<ExtendedValidationResult> {
  const { txHex, network, apiKey, provider = 'koios' } = config;

  // Step 1: what the transaction needs
  const necessary = await necessaryData(txHex, network);

  // Step 2: fetch it from the chosen provider
  const fetchedData = await fetchValidationData(necessary, network, apiKey, provider);

  // Step 3: build the ValidationInputContext
  const validationContext = buildValidationContext(fetchedData, network);

  // Step 4: validate
  const validationResult = await validateTransaction(txHex, validationContext);

  // Step 5: UTxO info map for display purposes
  const utxoInfoMap = new Map<string, KoiosUtxoInfo>();
  for (const utxo of fetchedData.utxoInfos) {
    const key = `${utxo.tx_hash}#${utxo.tx_index}`;
    utxoInfoMap.set(key, utxo);
  }

  return {
    result: validationResult,
    utxoInfoMap,
    fetchedContext: fetchedData,
  };
}

/**
 * Build ValidationInputContext from pre-fetched data
 * Useful when you want to manage data fetching yourself
 */
export function buildValidationContext(
  fetchedData: FetchedValidationData,
  network: NetworkType
): ValidationInputContext {
  return {
    utxoSet: fetchedData.utxoSet,
    protocolParameters: fetchedData.protocolParameters,
    slot: fetchedData.slot,
    accountContexts: fetchedData.accountContexts,
    drepContexts: fetchedData.drepContexts,
    poolContexts: fetchedData.poolContexts,
    govActionContexts: fetchedData.govActionContexts,
    lastEnactedGovAction: fetchedData.lastEnactedGovAction,
    currentCommitteeMembers: fetchedData.currentCommitteeMembers,
    potentialCommitteeMembers: fetchedData.potentialCommitteeMembers,
    constitution: fetchedData.constitution,
    treasuryValue: fetchedData.treasuryValue,
    networkType: network,
  };
}
