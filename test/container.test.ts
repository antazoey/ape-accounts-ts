import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { AccountContainer } from '../src/container.js'
import { AliasError, InvalidPasswordError } from '../src/errors.js'

const fast = { n: 1024, r: 8, p: 1 } as const
const PK = '0x4646464646464646464646464646464646464646464646464646464646464646'

let dir: string
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'ape-accounts-'))
})
afterAll(async () => {
  await rm(dir, { recursive: true, force: true })
})

describe('AccountContainer', () => {
  it('starts empty and grows as accounts are imported', async () => {
    const container = new AccountContainer({ dataFolder: dir })
    expect(await container.aliases()).toEqual([])

    await container.importFromPrivateKey({
      alias: 'alice',
      privateKey: PK,
      passphrase: 'pw',
      encrypt: fast,
    })
    expect(await container.aliases()).toEqual(['alice'])
    expect(await container.has('alice')).toBe(true)
  })

  it('persists keystores as <alias>.json files', async () => {
    const path = join(dir, 'alice.json')
    const raw = await readFile(path, 'utf8')
    const parsed = JSON.parse(raw)
    expect(parsed.version).toBe(3)
  })

  it('refuses to overwrite an existing alias', async () => {
    const container = new AccountContainer({ dataFolder: dir })
    await expect(
      container.importFromPrivateKey({
        alias: 'alice',
        privateKey: PK,
        passphrase: 'pw',
        encrypt: fast,
      }),
    ).rejects.toBeInstanceOf(AliasError)
  })

  it('loads an account and signs with it', async () => {
    const container = new AccountContainer({ dataFolder: dir })
    const account = await container.load('alice')
    expect(account.alias).toBe('alice')
    await account.unlock('pw')
    const sig = await account.signMessage({ message: 'hi' })
    expect(sig.startsWith('0x')).toBe(true)
  })

  it('exportPrivateKey round-trips', async () => {
    const container = new AccountContainer({ dataFolder: dir })
    const pk = await container.exportPrivateKey('alice', 'pw')
    expect(pk.toLowerCase()).toBe(PK.toLowerCase())
  })

  it('changePassword rewrites the keystore on disk', async () => {
    const container = new AccountContainer({ dataFolder: dir })
    await container.changePassword('alice', 'pw', 'newpw')
    await expect(container.exportPrivateKey('alice', 'pw')).rejects.toBeInstanceOf(
      InvalidPasswordError,
    )
    const pk = await container.exportPrivateKey('alice', 'newpw')
    expect(pk.toLowerCase()).toBe(PK.toLowerCase())
  })

  it('delete refuses with wrong password, succeeds with right one', async () => {
    const container = new AccountContainer({ dataFolder: dir })
    await expect(container.delete('alice', 'wrong')).rejects.toBeInstanceOf(InvalidPasswordError)
    await container.delete('alice', 'newpw')
    expect(await container.has('alice')).toBe(false)
  })

  it('generate creates a fresh account on disk', async () => {
    const container = new AccountContainer({ dataFolder: dir })
    const { mnemonic, path } = await container.generate({
      alias: 'bob',
      passphrase: 'pw',
      encrypt: fast,
    })
    expect(mnemonic.split(' ').length).toBe(12)
    expect(path).toBe(join(dir, 'bob.json'))
    expect(await container.has('bob')).toBe(true)
  })
})
