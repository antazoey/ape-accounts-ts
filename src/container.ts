import { mkdir, readFile, readdir, stat, unlink, writeFile } from 'node:fs/promises'
import { basename, extname, join } from 'node:path'
import { KeyfileAccount } from './account.js'
import { decryptKeystore } from './keystore.js'
import {
  generateAccount as _generateAccount,
  importFromMnemonic as _importFromMnemonic,
  importFromPrivateKey as _importFromPrivateKey,
  validateAlias,
  type GenerateAccountOptions,
  type GenerateAccountResult,
  type ImportFromMnemonicOptions,
  type ImportFromPrivateKeyOptions,
  type ImportResult,
} from './generate.js'
import { DEFAULT_ACCOUNTS_DIR } from './paths.js'
import { AccountsError, AliasError } from './errors.js'
import type { Hex, KeystoreV3 } from './types.js'

export interface AccountContainerOptions {
  /** Directory holding `<alias>.json` keystore files. Defaults to `~/.ape/accounts`. */
  dataFolder?: string
}

/**
 * Mirror of ape's `AccountContainer`: lists, loads, and persists keyfile
 * accounts under a data folder (default `~/.ape/accounts`).
 *
 * Each method is the programmatic equivalent of a `ape accounts <cmd>` CLI
 * command:
 *
 *   - aliases()/list()      → `ape accounts list`
 *   - generate()            → `ape accounts generate <alias>`
 *   - importFromPrivateKey()→ `ape accounts import <alias>`
 *   - importFromMnemonic()  → `ape accounts import <alias> --use-mnemonic`
 *   - exportPrivateKey()    → `ape accounts export <alias>`
 *   - changePassword()      → `ape accounts change-password <alias>`
 *   - delete()              → `ape accounts delete <alias>`
 */
export class AccountContainer {
  readonly dataFolder: string
  #cache = new Map<string, KeyfileAccount>()

  constructor(opts: AccountContainerOptions = {}) {
    this.dataFolder = opts.dataFolder ?? DEFAULT_ACCOUNTS_DIR
  }

  pathFor(alias: string): string {
    return join(this.dataFolder, `${alias}.json`)
  }

  async ensureFolder(): Promise<void> {
    try {
      await stat(this.dataFolder)
    } catch {
      await mkdir(this.dataFolder, { recursive: true })
    }
  }

  async aliases(): Promise<string[]> {
    try {
      const entries = await readdir(this.dataFolder)
      return entries
        .filter((f) => extname(f) === '.json')
        .map((f) => basename(f, '.json'))
        .sort()
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw err
    }
  }

  async has(alias: string): Promise<boolean> {
    return (await this.aliases()).includes(alias)
  }

  async load(alias: string): Promise<KeyfileAccount> {
    const cached = this.#cache.get(alias)
    if (cached) return cached
    const raw = await readFile(this.pathFor(alias), 'utf8')
    const account = new KeyfileAccount(JSON.parse(raw) as KeystoreV3, { alias })
    this.#cache.set(alias, account)
    return account
  }

  async *accounts(): AsyncIterableIterator<KeyfileAccount> {
    for (const alias of await this.aliases()) {
      yield this.load(alias)
    }
  }

  async list(): Promise<KeyfileAccount[]> {
    const out: KeyfileAccount[] = []
    for await (const a of this.accounts()) out.push(a)
    return out
  }

  async save(alias: string, keystore: KeystoreV3, { overwrite = false } = {}): Promise<string> {
    validateAlias(alias)
    await this.ensureFolder()
    if (!overwrite && (await this.has(alias))) {
      throw new AliasError(`Account '${alias}' already exists.`)
    }
    const path = this.pathFor(alias)
    await writeFile(path, JSON.stringify(keystore), 'utf8')
    this.#cache.delete(alias)
    return path
  }

  async delete(alias: string, passphrase: string): Promise<void> {
    if (!(await this.has(alias))) {
      throw new AccountsError(`Account '${alias}' does not exist.`)
    }
    const account = await this.load(alias)
    await decryptKeystore(account.keystore, passphrase) // verifies password; throws if wrong
    await unlink(this.pathFor(alias))
    this.#cache.delete(alias)
  }

  async changePassword(alias: string, oldPassphrase: string, newPassphrase: string): Promise<string> {
    const account = await this.load(alias)
    const fresh = await account.changePassword(oldPassphrase, newPassphrase)
    const path = this.pathFor(alias)
    await writeFile(path, JSON.stringify(fresh), 'utf8')
    this.#cache.delete(alias)
    return path
  }

  async exportPrivateKey(alias: string, passphrase: string): Promise<Hex> {
    const account = await this.load(alias)
    return account.exportPrivateKey(passphrase)
  }

  async generate(
    opts: GenerateAccountOptions & { alias: string },
  ): Promise<GenerateAccountResult & { path: string }> {
    validateAlias(opts.alias)
    if (await this.has(opts.alias)) {
      throw new AliasError(`Account '${opts.alias}' already exists.`)
    }
    const result = await _generateAccount(opts)
    const path = await this.save(opts.alias, result.keystore)
    return { ...result, path }
  }

  async importFromPrivateKey(
    opts: ImportFromPrivateKeyOptions & { alias: string },
  ): Promise<ImportResult & { path: string }> {
    validateAlias(opts.alias)
    if (await this.has(opts.alias)) {
      throw new AliasError(`Account '${opts.alias}' already exists.`)
    }
    const result = await _importFromPrivateKey(opts)
    const path = await this.save(opts.alias, result.keystore)
    return { ...result, path }
  }

  async importFromMnemonic(
    opts: ImportFromMnemonicOptions & { alias: string },
  ): Promise<ImportResult & { path: string }> {
    validateAlias(opts.alias)
    if (await this.has(opts.alias)) {
      throw new AliasError(`Account '${opts.alias}' already exists.`)
    }
    const result = await _importFromMnemonic(opts)
    const path = await this.save(opts.alias, result.keystore)
    return { ...result, path }
  }
}
