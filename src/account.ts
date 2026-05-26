import type { Address, Hex } from 'viem'
import { privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts'
import { decryptKeystore, encryptKeystore } from './keystore.js'
import { AccountLockedError } from './errors.js'
import type { KeystoreEncryptOptions, KeystoreV3 } from './types.js'

export interface KeyfileAccountOptions {
  alias?: string
}

/**
 * Browser- and Node-friendly handle on a single Ape keyfile (Web3 Secret Storage v3).
 *
 * Construct from a parsed keystore object or JSON string. The account starts
 * locked; call `unlock(passphrase)` to enable signing. The decrypted private
 * key never leaves this instance unless `exportPrivateKey` is called.
 */
export class KeyfileAccount {
  readonly keystore: KeystoreV3
  alias: string
  #signer: PrivateKeyAccount | null = null

  constructor(keystore: KeystoreV3, opts: KeyfileAccountOptions = {}) {
    this.keystore = keystore
    this.alias = opts.alias ?? ''
  }

  static fromKeystore(keystore: KeystoreV3, opts: KeyfileAccountOptions = {}): KeyfileAccount {
    return new KeyfileAccount(keystore, opts)
  }

  static fromKeystoreJson(json: string, opts: KeyfileAccountOptions = {}): KeyfileAccount {
    return new KeyfileAccount(JSON.parse(json) as KeystoreV3, opts)
  }

  get address(): Address {
    const a = this.keystore.address
    return (a.startsWith('0x') || a.startsWith('0X') ? a : `0x${a}`) as Address
  }

  get publicKey(): Hex | undefined {
    const pk = this.keystore.public_key
    if (!pk) return undefined
    return (pk.startsWith('0x') ? pk : `0x${pk}`) as Hex
  }

  get locked(): boolean {
    return this.#signer === null
  }

  async unlock(passphrase: string): Promise<void> {
    const privateKey = await decryptKeystore(this.keystore, passphrase)
    this.#signer = privateKeyToAccount(privateKey)
  }

  lock(): void {
    this.#signer = null
  }

  /** Returns the underlying viem `PrivateKeyAccount` so it can be passed to
   *  `createWalletClient({ account })` or similar. Throws if locked. */
  toLocalAccount(): PrivateKeyAccount {
    return this.#requireSigner()
  }

  async exportPrivateKey(passphrase: string): Promise<Hex> {
    return decryptKeystore(this.keystore, passphrase)
  }

  /** Returns a *new* keystore encrypted with `newPassphrase`. Does not
   *  mutate this account's keystore; callers persist the result. */
  async changePassword(
    oldPassphrase: string,
    newPassphrase: string,
    opts?: KeystoreEncryptOptions,
  ): Promise<KeystoreV3> {
    const pk = await decryptKeystore(this.keystore, oldPassphrase)
    return encryptKeystore(pk, newPassphrase, opts)
  }

  #requireSigner(): PrivateKeyAccount {
    if (!this.#signer) throw new AccountLockedError(this.alias || undefined)
    return this.#signer
  }

  async signMessage(
    args: Parameters<PrivateKeyAccount['signMessage']>[0],
  ): Promise<Awaited<ReturnType<PrivateKeyAccount['signMessage']>>> {
    return this.#requireSigner().signMessage(args)
  }

  async signTypedData(
    args: Parameters<PrivateKeyAccount['signTypedData']>[0],
  ): Promise<Awaited<ReturnType<PrivateKeyAccount['signTypedData']>>> {
    return this.#requireSigner().signTypedData(args)
  }

  async signTransaction(
    transaction: Parameters<PrivateKeyAccount['signTransaction']>[0],
    args?: Parameters<PrivateKeyAccount['signTransaction']>[1],
  ): Promise<Awaited<ReturnType<PrivateKeyAccount['signTransaction']>>> {
    return this.#requireSigner().signTransaction(transaction, args as never)
  }

  async signAuthorization(
    args: Parameters<PrivateKeyAccount['signAuthorization']>[0],
  ): Promise<Awaited<ReturnType<PrivateKeyAccount['signAuthorization']>>> {
    return this.#requireSigner().signAuthorization(args)
  }

  /** Raw 32-byte digest signing. Dangerous — caller is responsible for the
   *  preimage. Prefer signMessage / signTypedData when possible. */
  async sign(
    args: Parameters<PrivateKeyAccount['sign']>[0],
  ): Promise<Awaited<ReturnType<PrivateKeyAccount['sign']>>> {
    return this.#requireSigner().sign(args)
  }
}
