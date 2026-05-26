export class AccountsError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AccountsError'
  }
}

export class InvalidPasswordError extends AccountsError {
  constructor() {
    super('Invalid password')
    this.name = 'InvalidPasswordError'
  }
}

export class AccountLockedError extends AccountsError {
  constructor(alias?: string) {
    super(alias ? `Account '${alias}' is locked` : 'Account is locked')
    this.name = 'AccountLockedError'
  }
}

export class AliasError extends AccountsError {
  constructor(message: string) {
    super(message)
    this.name = 'AliasError'
  }
}
