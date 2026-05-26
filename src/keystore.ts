import { scryptAsync } from '@noble/hashes/scrypt'
import { keccak_256 } from '@noble/hashes/sha3'
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils'
import { ctr } from '@noble/ciphers/aes'
import type { Hex } from 'viem'
import { privateKeyToAddress } from 'viem/accounts'
import { AccountsError, InvalidPasswordError } from './errors.js'
import type {
  KeystoreEncryptOptions,
  KeystoreV3,
  ScryptKdfParams,
} from './types.js'

const textEncoder = new TextEncoder()

function getRandomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n)
  const c = globalThis.crypto
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new AccountsError('A secure crypto.getRandomValues() is required.')
  }
  c.getRandomValues(buf)
  return buf
}

function randomUuidV4(): string {
  const c = globalThis.crypto
  if (c && typeof c.randomUUID === 'function') return c.randomUUID()
  const b = getRandomBytes(16)
  b[6] = (b[6]! & 0x0f) | 0x40
  b[8] = (b[8]! & 0x3f) | 0x80
  const h = bytesToHex(b)
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

function stripHex(s: string): string {
  return s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s
}

async function deriveScryptKey(passphrase: string, params: ScryptKdfParams): Promise<Uint8Array> {
  return scryptAsync(textEncoder.encode(passphrase), hexToBytes(params.salt), {
    N: params.n,
    r: params.r,
    p: params.p,
    dkLen: params.dklen,
  })
}

export async function decryptKeystore(keystore: KeystoreV3, passphrase: string): Promise<Hex> {
  if (keystore.version !== 3) {
    throw new AccountsError(`Unsupported keystore version: ${keystore.version}`)
  }
  if (keystore.crypto.cipher !== 'aes-128-ctr') {
    throw new AccountsError(`Unsupported cipher: ${keystore.crypto.cipher}`)
  }
  if (keystore.crypto.kdf !== 'scrypt') {
    throw new AccountsError(`Unsupported KDF: ${keystore.crypto.kdf}. Only scrypt is supported.`)
  }

  const derived = await deriveScryptKey(passphrase, keystore.crypto.kdfparams as ScryptKdfParams)
  const ciphertext = hexToBytes(stripHex(keystore.crypto.ciphertext))
  const expectedMac = bytesToHex(keccak_256(concatBytes(derived.slice(16, 32), ciphertext)))
  if (expectedMac !== stripHex(keystore.crypto.mac).toLowerCase()) {
    throw new InvalidPasswordError()
  }

  const key = derived.slice(0, 16)
  const iv = hexToBytes(stripHex(keystore.crypto.cipherparams.iv))
  const plain = ctr(key, iv).decrypt(ciphertext)
  return `0x${bytesToHex(plain)}` as Hex
}

export async function encryptKeystore(
  privateKey: Hex | string,
  passphrase: string,
  opts: KeystoreEncryptOptions = {},
): Promise<KeystoreV3> {
  const n = opts.n ?? 262144
  const r = opts.r ?? 8
  const p = opts.p ?? 1
  const dklen = opts.dklen ?? 32
  const salt = opts.salt ?? getRandomBytes(32)
  const iv = opts.iv ?? getRandomBytes(16)
  const id = opts.uuid ?? randomUuidV4()

  const pkBytes = hexToBytes(stripHex(privateKey))
  if (pkBytes.length !== 32) {
    throw new AccountsError(`Invalid private key length: ${pkBytes.length} (expected 32 bytes).`)
  }
  const pkHex = `0x${bytesToHex(pkBytes)}` as Hex

  const derived = await scryptAsync(textEncoder.encode(passphrase), salt, {
    N: n, r, p, dkLen: dklen,
  })
  const key = derived.slice(0, 16)
  const ciphertext = ctr(key, iv).encrypt(pkBytes)
  const mac = bytesToHex(keccak_256(concatBytes(derived.slice(16, 32), ciphertext)))

  // Ape stores the address as checksummed hex without a 0x prefix.
  const address = stripHex(privateKeyToAddress(pkHex))

  return {
    address,
    crypto: {
      cipher: 'aes-128-ctr',
      cipherparams: { iv: bytesToHex(iv) },
      ciphertext: bytesToHex(ciphertext),
      kdf: 'scrypt',
      kdfparams: { dklen, n, r, p, salt: bytesToHex(salt) },
      mac,
    },
    id,
    version: 3,
  }
}
