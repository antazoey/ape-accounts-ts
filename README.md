# ape-accounts

TypeScript library for reading and managing [Ape](https://github.com/ApeWorX/ape) keyfile accounts.
Works in Node.js (reads `~/.ape/accounts` directly) and in the browser (you supply the keystore JSON).

It's a port of the [`ape_accounts`](https://github.com/ApeWorX/ape/tree/main/src/ape_accounts) core plugin —
same keystore format (Web3 Secret Storage v3, scrypt + AES-128-CTR), same alias conventions, same
default HD path.

## Install

```sh
npm install @apeworx/ape-accounts
```

Peer-friendly with [viem](https://viem.sh/) — signing is delegated to viem's `PrivateKeyAccount`,
so a `KeyfileAccount` plugs into `createWalletClient({ account })` once it's unlocked.

## Browser usage

In the browser there's no filesystem, so the caller is responsible for loading and persisting
keystore JSON. See [Browser persistence](#browser-persistence) below for storage strategies.

```ts
import { KeyfileAccount, generateAccount, importFromPrivateKey } from '@apeworx/ape-accounts'

// Load from a JSON string (file picker, fetch, IndexedDB, chrome.storage, ...)
const account = KeyfileAccount.fromKeystoreJson(keystoreJson, { alias: 'main' })

await account.unlock('hunter2')

// Sign anything viem can sign
const sig    = await account.signMessage({ message: 'hello' })
const typed  = await account.signTypedData({ domain, types, primaryType, message })
const rawTx  = await account.signTransaction(tx)
const auth7702 = await account.signAuthorization({ contractAddress, chainId, nonce })

// Or hand the underlying viem account to a wallet client
import { createWalletClient, http } from 'viem'
const client = createWalletClient({ account: account.toLocalAccount(), transport: http() })

// Create a new account in-browser (returns a keystore you persist yourself)
const { account: fresh, mnemonic, keystore } = await generateAccount({
  alias: 'main',
  passphrase: 'hunter2',
})
await myStorage.put('main', JSON.stringify(keystore))

// Import an existing private key
const { keystore: ks } = await importFromPrivateKey({
  alias: 'imported',
  privateKey: '0x4646...',
  passphrase: 'hunter2',
})
```

## Node.js usage

In Node there's a fs-backed `AccountContainer` that mirrors ape's behavior, defaulting to
`~/.ape/accounts` (or `$APE_HOME/accounts`):

```ts
import { AccountContainer } from '@apeworx/ape-accounts/node'

const container = new AccountContainer() // defaults to ~/.ape/accounts
// or: new AccountContainer({ dataFolder: '/custom/path' })

for (const alias of await container.aliases()) {
  console.log(alias)
}

const account = await container.load('antazoey')
await account.unlock(process.env.APE_PASSPHRASE!)
const sig = await account.signMessage({ message: 'hello' })
```

### `ape accounts` CLI mapping

Each subcommand has a programmatic equivalent on `AccountContainer`:

| `ape accounts ...`               | TypeScript                                                         |
|----------------------------------|--------------------------------------------------------------------|
| `list`                           | `container.aliases()` / `container.list()`                         |
| `generate <alias>`               | `container.generate({ alias, passphrase, hdPath?, wordCount? })`   |
| `import <alias>`                 | `container.importFromPrivateKey({ alias, privateKey, passphrase })`|
| `import <alias> --use-mnemonic`  | `container.importFromMnemonic({ alias, mnemonic, passphrase, hdPath? })` |
| `export <alias>`                 | `container.exportPrivateKey(alias, passphrase)`                    |
| `change-password <alias>`        | `container.changePassword(alias, oldPassphrase, newPassphrase)`    |
| `delete <alias>`                 | `container.delete(alias, passphrase)`                              |
| `auth set/rm`                    | `account.signAuthorization(...)` — broadcast via your own client   |

The EIP-7702 `auth` subcommands aren't bundled because broadcasting needs a connected RPC; this
library produces a signed authorization and lets the caller decide how to send it.

## Browser persistence

The browser has no `~/.ape/accounts`. The library deliberately stops at "give me a keystore JSON,
I'll do the crypto" — you choose where to keep the JSON. Trade-offs by storage backend:

| Backend                  | Capacity   | Survives reload | Survives reinstall | Notes                                           |
|--------------------------|------------|-----------------|--------------------|-------------------------------------------------|
| `localStorage`           | ~5 MB      | yes             | no                 | Synchronous, string-only. Fine for tiny wallets.|
| `IndexedDB`              | hundreds MB| yes             | no                 | Async, structured. The right default for web apps.|
| `chrome.storage.local`   | ~10 MB     | yes             | no                 | Extensions only. Sync option (`.sync`) is limited.|
| File System Access API   | unlimited  | yes             | yes (user-chosen)  | Lets you point a browser wallet at the user's actual `~/.ape/accounts` folder on disk — same files Ape uses.|
| OPFS                     | hundreds MB| yes             | no                 | Origin-Private FS, browser-managed, not user-visible.|

Recommended approach for a browser wallet:

1. **Keep keystores encrypted at rest.** The keystore format is already designed for this — scrypt
   with `n=262144` makes brute-forcing the passphrase slow. So you can store the keystore JSON in
   any of the above, including `localStorage`, without further encryption. The on-disk format on
   `~/.ape/accounts` is the same.
2. **Never persist the decrypted private key.** Call `account.unlock(passphrase)` per session
   (or per signing operation) and `account.lock()` when done. The signer lives in memory only.
3. **Default to IndexedDB.** It's async-friendly, has plenty of room, and supports indexes if you
   want alias lookup. A minimal adapter is just three methods (`get`, `put`, `delete`).
4. **For an extension, use `chrome.storage.local`.** Service-worker friendly and isolated per
   extension. Stay under the 10 MB quota — keystores are small (~600 bytes each), so this is fine
   for thousands of accounts.

A sketch of a browser `AccountContainer`-like wrapper around IndexedDB (~30 lines, not shipped):

```ts
import { KeyfileAccount, type KeystoreV3 } from '@apeworx/ape-accounts'

class BrowserAccountStore {
  constructor(private db: IDBDatabase, private store = 'keystores') {}

  async aliases(): Promise<string[]> {
    return new Promise((res, rej) => {
      const req = this.db.transaction(this.store).objectStore(this.store).getAllKeys()
      req.onsuccess = () => res(req.result as string[])
      req.onerror = () => rej(req.error)
    })
  }

  async load(alias: string): Promise<KeyfileAccount> {
    const json = await new Promise<KeystoreV3>((res, rej) => {
      const req = this.db.transaction(this.store).objectStore(this.store).get(alias)
      req.onsuccess = () => res(req.result)
      req.onerror = () => rej(req.error)
    })
    return new KeyfileAccount(json, { alias })
  }

  async save(alias: string, keystore: KeystoreV3): Promise<void> {
    await new Promise<void>((res, rej) => {
      const tx = this.db.transaction(this.store, 'readwrite')
      tx.objectStore(this.store).put(keystore, alias)
      tx.oncomplete = () => res()
      tx.onerror = () => rej(tx.error)
    })
  }
}
```

When the ext wallet matures, this could become a first-class `BrowserAccountContainer` exported
from `@apeworx/ape-accounts/browser`. Not in v0 — happy to add it.

## API reference

### Universal (`@apeworx/ape-accounts`)

- `class KeyfileAccount`
  - `constructor(keystore, { alias? })` / `static fromKeystore(keystore, opts?)` / `static fromKeystoreJson(json, opts?)`
  - `address: Address`, `publicKey?: Hex`, `alias: string`, `locked: boolean`
  - `unlock(passphrase)`, `lock()`
  - `signMessage`, `signTypedData`, `signTransaction`, `signAuthorization`, `sign({ hash })` — same shapes as viem's `PrivateKeyAccount`
  - `toLocalAccount()` — returns the viem `PrivateKeyAccount` (must be unlocked)
  - `exportPrivateKey(passphrase): Promise<Hex>`
  - `changePassword(old, new, encryptOpts?): Promise<KeystoreV3>` — returns a *new* keystore, caller persists
- `generateAccount({ passphrase, alias?, hdPath?, wordCount? }): { account, mnemonic, keystore }`
- `importFromMnemonic({ mnemonic, passphrase, alias?, hdPath? }): { account, keystore }`
- `importFromPrivateKey({ privateKey, passphrase, alias? }): { account, keystore }`
- `decryptKeystore(keystore, passphrase): Promise<Hex>` — low-level
- `encryptKeystore(privateKey, passphrase, opts?): Promise<KeystoreV3>` — low-level
- `ETHEREUM_DEFAULT_PATH = "m/44'/60'/0'/0/0"`
- Errors: `AccountsError`, `InvalidPasswordError`, `AccountLockedError`, `AliasError`

### Node (`@apeworx/ape-accounts/node`)

Everything above, plus:

- `class AccountContainer({ dataFolder? })` — defaults to `$APE_HOME/accounts` or `~/.ape/accounts`
- `APE_HOME`, `DEFAULT_ACCOUNTS_DIR`

## Development

```sh
npm install
npm run typecheck
npm test
npm run build      # dual ESM + CJS in dist/
```

## License

MIT
