import type { Address, Hex } from 'viem'

export const ETHEREUM_DEFAULT_PATH = "m/44'/60'/0'/0/0"

export interface ScryptKdfParams {
  dklen: number
  n: number
  r: number
  p: number
  salt: string
}

export interface Pbkdf2KdfParams {
  dklen: number
  c: number
  prf: string
  salt: string
}

export interface KeystoreCryptoParams {
  cipher: 'aes-128-ctr'
  cipherparams: { iv: string }
  ciphertext: string
  kdf: 'scrypt' | 'pbkdf2'
  kdfparams: ScryptKdfParams | Pbkdf2KdfParams
  mac: string
}

export interface KeystoreV3 {
  address: string
  crypto: KeystoreCryptoParams
  id: string
  version: 3
  public_key?: string
}

export interface KeystoreEncryptOptions {
  /** scrypt cost parameter. Ape's default is 262144. */
  n?: number
  /** scrypt block size. Default 8. */
  r?: number
  /** scrypt parallelization. Default 1. */
  p?: number
  /** derived-key length. Default 32. */
  dklen?: number
  /** Override the 32-byte salt (testing/determinism). */
  salt?: Uint8Array
  /** Override the 16-byte AES IV (testing/determinism). */
  iv?: Uint8Array
  /** Override the keystore UUID (testing/determinism). */
  uuid?: string
}

export type WordCount = 12 | 15 | 18 | 21 | 24

export type { Address, Hex }
