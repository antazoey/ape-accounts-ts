import { homedir } from 'node:os'
import { join } from 'node:path'

export const APE_HOME = process.env.APE_HOME ?? join(homedir(), '.ape')
export const DEFAULT_ACCOUNTS_DIR = join(APE_HOME, 'accounts')
