import { describe, expect, it } from 'vitest'
import { recoverMessageAddress, recoverTypedDataAddress } from 'viem'
import { privateKeyToAddress } from 'viem/accounts'
import { KeyfileAccount } from '../src/account.js'
import { encryptKeystore } from '../src/keystore.js'
import { AccountLockedError } from '../src/errors.js'

const fast = { n: 1024, r: 8, p: 1 } as const
const PK = '0x4646464646464646464646464646464646464646464646464646464646464646'

async function makeAccount(pw = 'pw') {
  const keystore = await encryptKeystore(PK, pw, fast)
  return new KeyfileAccount(keystore, { alias: 'test' })
}

describe('KeyfileAccount', () => {
  it('exposes the checksummed address from the keystore', async () => {
    const account = await makeAccount()
    expect(account.address.toLowerCase()).toBe(privateKeyToAddress(PK).toLowerCase())
  })

  it('starts locked and unlocks with the correct passphrase', async () => {
    const account = await makeAccount('hunter2')
    expect(account.locked).toBe(true)
    await account.unlock('hunter2')
    expect(account.locked).toBe(false)
    account.lock()
    expect(account.locked).toBe(true)
  })

  it('throws AccountLockedError when signing while locked', async () => {
    const account = await makeAccount()
    await expect(account.signMessage({ message: 'hi' })).rejects.toBeInstanceOf(AccountLockedError)
  })

  it('signs personal messages that recover to the account address', async () => {
    const account = await makeAccount()
    await account.unlock('pw')
    const sig = await account.signMessage({ message: 'hello ape' })
    const recovered = await recoverMessageAddress({ message: 'hello ape', signature: sig })
    expect(recovered.toLowerCase()).toBe(account.address.toLowerCase())
  })

  it('signs EIP-712 typed data that recovers to the account address', async () => {
    const account = await makeAccount()
    await account.unlock('pw')
    const typedData = {
      domain: { name: 'Ape', version: '1', chainId: 1 },
      types: {
        Mail: [
          { name: 'from', type: 'address' },
          { name: 'note', type: 'string' },
        ],
      },
      primaryType: 'Mail',
      message: { from: account.address, note: 'hello' },
    } as const
    const sig = await account.signTypedData(typedData)
    const recovered = await recoverTypedDataAddress({ ...typedData, signature: sig })
    expect(recovered.toLowerCase()).toBe(account.address.toLowerCase())
  })

  it('exportPrivateKey returns the original key', async () => {
    const account = await makeAccount('pw')
    const exported = await account.exportPrivateKey('pw')
    expect(exported.toLowerCase()).toBe(PK.toLowerCase())
  })

  it('changePassword produces a keystore the new password can open', async () => {
    const account = await makeAccount('old')
    const fresh = await account.changePassword('old', 'new', fast)
    const reopened = new KeyfileAccount(fresh, { alias: 'test' })
    await reopened.unlock('new')
    expect(reopened.locked).toBe(false)
  })
})
