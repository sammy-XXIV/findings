# Security report: a malicious UTXO backend can silently burn a user's funds to miner fee on legacy (non-SegWit) inputs

**Component:** edge-currency-plugins (Edge wallet UTXO/Bitcoin-family currency plugin)
**Version / commit:** edge-currency-plugins v3.16.0, commit `d028130b3050f24a90cd7868bccbacecc104e3d5`
**Affected files:** `src/common/utxobased/keymanager/keymanager.ts` (makeTx), `src/common/utxobased/engine/UtxoEngineProcessor.ts`, `src/common/utxobased/network/blockbookApi.ts`, `src/common/plugin/PluginState.ts`
**Reporter severity estimate:** High — direct, user-unintended loss of funds, triggered by a server the Edge threat model treats as untrusted, with no user error. Bounded per input by the per-coin `maximumFeeRate` cap (~$500+ of BTC per input) and multipliable across inputs/transactions. Defer rating to Edge.

## Summary

When Edge builds a Bitcoin-family spend, the amount used for coin-selection and change is taken from the `value` field that the blockbook backend reports for each UTXO (`keymanager.ts:1119`). That value is only type-checked (`asString`, `blockbookApi.ts:44`) and is never reconciled against the real previous-transaction output, even though the wallet already holds the full previous transaction and uses it for signing.

For **legacy (non-SegWit) inputs** the ECDSA sighash does **not** commit to the input amount, so a signature produced against a *claimed* value is valid on the network regardless of the real value. Therefore a malicious or MITM'd backend that reports a UTXO's `value` as smaller than its real on-chain value makes the wallet build a transaction that spends the full real input but creates outputs sized to the lie — and the entire difference is burned to the miner as fee. The wallet displays only the small fee it computed from the lie; the real fee is hidden from the user.

SegWit inputs are **not** affected: BIP143 commits the input amount into the sighash, so the same lie yields a signature the network rejects.

## Root cause (code)

- `src/common/utxobased/network/blockbookApi.ts:44` — the blockbook UTXO response field is `value: asString`. No bound, no reconciliation.
- `src/common/utxobased/engine/UtxoEngineProcessor.ts:1704` — `value: cacheItem.blockbookUtxo.value`: the stored `UtxoData.value` is exactly the backend-reported value.
- `src/common/utxobased/keymanager/keymanager.ts:1119` — `value: parseInt(utxo.value)`: `makeTx` uses that value for coin-selection and change. For legacy inputs it also sets `input.nonWitnessUtxo = input.script` (the full previous transaction) for signing (`:1134`), but it never compares the prev-tx's actual output value to `utxo.value`. (`grep` for any value reconciliation in keymanager.ts returns nothing.)
- Backend reachability: `src/common/plugin/PluginState.ts:222` uses `infoPayload.blockbookServers` to populate the server pool, and `infoPayload` is delivered to the plugin by `updateInfoPayload` from the Edge info server with no structural validation of its contents in edge-core (`currency-pixie.ts:60-67`, `asObject(asJsonObject)`). A compromised info server can therefore repoint the wallet at an attacker-controlled blockbook; a network attacker can equivalently MITM the blockbook connection.

## Proof of concept (runnable, passes)

Add `test/common/utxobased/keymanager/coins/poc-lying-prevout.spec.ts` (attached) and run:

```
npm install --ignore-scripts
npx patch-package
node_modules/.bin/mocha --require sucrase/register --grep "lying-prevout"
```

Observed output:

```
PoC: lying-prevout legacy fee burn
  real prevout value : 90000
  claimed value      : 2000
  signed outputs sum : 1774
  fee wallet reports : ~226 sats
  REAL fee on-chain  : 88226 sats  (burned to miner, hidden from user)
  ✔ burns the real UTXO excess to fee when the backend lies the value is small
1 passing
```

A legacy p2pkh UTXO whose real previous-transaction output is 90000 sats is reported by the backend as 2000. The user sends 1000 sats. `makeTx` sizes the change against 2000, `signTx` produces a valid legacy signature spending the real 90000-sat input, and 88226 sats (98% of the input) are burned to the miner. `signTx` does not throw — the realized rate (~390 sat/vByte) is below the per-coin `maximumFeeRate` cap (~3641 sat/vByte for BTC), so the cap backstop never fires.

## Impact

- Direct loss of user funds to miner fee, with the user shown only the small claimed fee. No user error: the recipient and send amount the user chose are honored; the loss is entirely in the hidden fee.
- Triggered by a backend, which Edge's threat model treats as untrusted (reachable via a compromised Edge info server repointing `blockbookServers`, or a MITM of the blockbook connection).
- A colluding miner captures the burned fee; otherwise it is destroyed. Either way the user loses it.
- Per-input loss is bounded by `maximumFeeRate` × tx vBytes (for BTC, ~728000 sats ≈ several hundred USD per input), and an attacker can repeat across every legacy input and every spend.

## Limitations (honest)

- **Legacy (non-SegWit) inputs only.** SegWit (p2wpkh / p2wpkh-p2sh / p2wsh) commits the amount via BIP143, so the lie produces an invalid signature and the network rejects it. Users whose UTXOs are all native/wrapped SegWit are unaffected; users spending legacy UTXOs (older wallets, imported keys, legacy-address receives) are affected.
- Requires the attacker to control or MITM the UTXO backend the wallet uses.
- The PoC was run at the `makeTx`/`signTx` layer (the code that builds and signs the transaction); the full engine path that feeds `UtxoData.value` from `blockbookUtxo.value` is confirmed by source (`UtxoEngineProcessor.ts:1704`, `blockbookApi.ts:44`) but not exercised end-to-end in the PoC.

## Recommendation

For legacy inputs, derive the spent amount from the `nonWitnessUtxo` (the full previous transaction the wallet already holds and already uses for signing) at the input's `vout`, and reject any UTXO whose backend-reported `value` does not match it. Do not trust the backend-supplied `value` field for fee/change computation on inputs whose signature does not commit to the amount.

## Methodology

Source review of the UTXO spend/sign path plus a runnable PoC executed against the repo's own keymanager test harness (edge-currency-plugins v3.16.0, altcoin-js patch applied). No Edge production infrastructure or real funds were used; the PoC runs entirely locally with a throwaway test key.
