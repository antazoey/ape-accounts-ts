import { describe, expect, it } from 'vitest'
import { decryptKeystore, encryptKeystore } from '../src/keystore.js'
import { InvalidPasswordError } from '../src/errors.js'

// Fast scrypt params (use real defaults in production)
const fast = { n: 1024, r: 8, p: 1 } as const
const PK = '0x4646464646464646464646464646464646464646464646464646464646464646'

describe('keystore', () => {
  it('round-trips a private key through encrypt → decrypt', async () => {
    const keystore = await encryptKeystore(PK, 'hunter2', fast)
    expect(keystore.version).toBe(3)
    expect(keystore.crypto.cipher).toBe('aes-128-ctr')
    expect(keystore.crypto.kdf).toBe('scrypt')
    expect(keystore.crypto.kdfparams).toMatchObject({ n: 1024, r: 8, p: 1, dklen: 32 })
    expect(keystore.address).toMatch(/^[0-9a-fA-F]{40}$/)
    const decoded = await decryptKeystore(keystore, 'hunter2')
    expect(decoded.toLowerCase()).toBe(PK.toLowerCase())
  })

  it('throws InvalidPasswordError when password is wrong', async () => {
    const keystore = await encryptKeystore(PK, 'hunter2', fast)
    await expect(decryptKeystore(keystore, 'nope')).rejects.toBeInstanceOf(InvalidPasswordError)
  })

  it('accepts private keys with or without the 0x prefix', async () => {
    const k1 = await encryptKeystore(PK, 'pw', fast)
    const k2 = await encryptKeystore(PK.slice(2), 'pw', fast)
    expect(k1.address.toLowerCase()).toBe(k2.address.toLowerCase())
  })

  it('produces a unique salt / iv / id on each call', async () => {
    const a = await encryptKeystore(PK, 'pw', fast)
    const b = await encryptKeystore(PK, 'pw', fast)
    expect(a.id).not.toBe(b.id)
    expect(a.crypto.cipherparams.iv).not.toBe(b.crypto.cipherparams.iv)
    expect((a.crypto.kdfparams as { salt: string }).salt).not.toBe(
      (b.crypto.kdfparams as { salt: string }).salt,
    )
  })

  it('rejects unsupported keystore versions', async () => {
    const keystore = await encryptKeystore(PK, 'pw', fast)
    const bad = { ...keystore, version: 1 as unknown as 3 }
    await expect(decryptKeystore(bad, 'pw')).rejects.toThrow(/Unsupported keystore version/)
  })
})
