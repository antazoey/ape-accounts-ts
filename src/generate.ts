import { bytesToHex } from '@noble/hashes/utils'
import {
  english,
  generateMnemonic,
  mnemonicToAccount,
} from 'viem/accounts'
import type { Hex } from 'viem'
import { KeyfileAccount } from './account.js'
import { encryptKeystore } from './keystore.js'
import { AccountsError, AliasError } from './errors.js'
import {
  ETHEREUM_DEFAULT_PATH,
  type KeystoreEncryptOptions,
  type KeystoreV3,
  type WordCount,
} from './types.js'

const WORD_COUNT_TO_STRENGTH: Record<WordCount, 128 | 160 | 192 | 224 | 256> = {
  12: 128,
  15: 160,
  18: 192,
  21: 224,
  24: 256,
}

const ALIAS_PATTERN = /^[A-Za-z0-9_.\-]+$/

export function validateAlias(alias: string): string {
  if (!alias) throw new AliasError('Alias cannot be empty.')
  if (!ALIAS_PATTERN.test(alias)) {
    throw new AliasError(
      `Alias '${alias}' has invalid characters. Use letters, digits, '_', '.', or '-'.`,
    )
  }
  return alias
}

export function validatePassphrase(passphrase: string): string {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new AccountsError('Passphrase cannot be empty.')
  }
  return passphrase
}

export interface GenerateAccountOptions {
  passphrase: string
  alias?: string
  hdPath?: string
  wordCount?: WordCount
  encrypt?: KeystoreEncryptOptions
}

export interface GenerateAccountResult {
  account: KeyfileAccount
  mnemonic: string
  keystore: KeystoreV3
}

export interface ImportFromMnemonicOptions {
  mnemonic: string
  passphrase: string
  alias?: string
  hdPath?: string
  encrypt?: KeystoreEncryptOptions
}

export interface ImportFromPrivateKeyOptions {
  privateKey: Hex | string
  passphrase: string
  alias?: string
  encrypt?: KeystoreEncryptOptions
}

export interface ImportResult {
  account: KeyfileAccount
  keystore: KeystoreV3
}

export async function generateAccount(opts: GenerateAccountOptions): Promise<GenerateAccountResult> {
  validatePassphrase(opts.passphrase)
  if (opts.alias !== undefined) validateAlias(opts.alias)
  const wordCount: WordCount = opts.wordCount ?? 12
  const mnemonic = generateMnemonic(english, WORD_COUNT_TO_STRENGTH[wordCount])
  const imported = await importFromMnemonic({
    mnemonic,
    passphrase: opts.passphrase,
    alias: opts.alias,
    hdPath: opts.hdPath,
    encrypt: opts.encrypt,
  })
  return { ...imported, mnemonic }
}

export async function importFromMnemonic(opts: ImportFromMnemonicOptions): Promise<ImportResult> {
  validatePassphrase(opts.passphrase)
  if (opts.alias !== undefined) validateAlias(opts.alias)
  const path = opts.hdPath ?? ETHEREUM_DEFAULT_PATH
  const hd = mnemonicToAccount(opts.mnemonic, { path: path as `m/44'/60'/${string}` })
  const pkBytes = hd.getHdKey().privateKey
  if (!pkBytes) throw new AccountsError('Failed to derive a private key from the mnemonic.')
  const privateKey = `0x${bytesToHex(pkBytes)}` as Hex
  return importFromPrivateKey({
    privateKey,
    passphrase: opts.passphrase,
    alias: opts.alias,
    encrypt: opts.encrypt,
  })
}

export async function importFromPrivateKey(opts: ImportFromPrivateKeyOptions): Promise<ImportResult> {
  validatePassphrase(opts.passphrase)
  if (opts.alias !== undefined) validateAlias(opts.alias)
  const keystore = await encryptKeystore(opts.privateKey, opts.passphrase, opts.encrypt)
  const account = new KeyfileAccount(keystore, { alias: opts.alias ?? '' })
  return { account, keystore }
}
