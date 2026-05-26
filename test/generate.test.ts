import { describe, expect, it } from 'vitest'
import { privateKeyToAddress } from 'viem/accounts'
import {
  generateAccount,
  importFromMnemonic,
  importFromPrivateKey,
  validateAlias,
} from '../src/generate.js'
import { AliasError } from '../src/errors.js'

const fast = { n: 1024, r: 8, p: 1 } as const
const PK = '0x4646464646464646464646464646464646464646464646464646464646464646'

describe('generate / import helpers', () => {
  it('generateAccount returns a usable mnemonic + unlockable keystore', async () => {
    const { account, mnemonic, keystore } = await generateAccount({
      passphrase: 'pw',
      alias: 'fresh',
      encrypt: fast,
    })
    expect(mnemonic.split(' ').length).toBe(12)
    expect(keystore.address).toMatch(/^[0-9a-fA-F]{40}$/)
    expect(account.locked).toBe(true)
    await account.unlock('pw')
    expect(account.locked).toBe(false)
  })

  it('generateAccount supports 24-word mnemonics', async () => {
    const { mnemonic } = await generateAccount({ passphrase: 'pw', wordCount: 24, encrypt: fast })
    expect(mnemonic.split(' ').length).toBe(24)
  })

  it('importFromPrivateKey produces a keystore for the matching address', async () => {
    const { keystore } = await importFromPrivateKey({
      privateKey: PK,
      passphrase: 'pw',
      alias: 'imported',
      encrypt: fast,
    })
    expect(keystore.address.toLowerCase()).toBe(privateKeyToAddress(PK).slice(2).toLowerCase())
  })

  it('importFromMnemonic respects a custom HD path', async () => {
    const mnemonic =
      'test test test test test test test test test test test junk'
    const { account: a0 } = await importFromMnemonic({
      mnemonic,
      passphrase: 'pw',
      encrypt: fast,
    })
    const { account: a1 } = await importFromMnemonic({
      mnemonic,
      passphrase: 'pw',
      hdPath: "m/44'/60'/0'/0/1",
      encrypt: fast,
    })
    expect(a0.address.toLowerCase()).not.toBe(a1.address.toLowerCase())
  })

  it('validateAlias rejects illegal characters', () => {
    expect(() => validateAlias('a b')).toThrow(AliasError)
    expect(() => validateAlias('')).toThrow(AliasError)
    expect(validateAlias('my-alias_1.test')).toBe('my-alias_1.test')
  })
})
