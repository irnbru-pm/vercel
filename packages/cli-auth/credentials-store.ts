import { readSession, writeSession } from "./irnbru.js";
import { createHash } from 'node:crypto';
import assert from 'node:assert';
import * as cliConfig from '@vercel/cli-config';
import type {
  AuthConfig as SharedAuthConfig,
  CredStorage,
  CredentialsStorageLocation,
  GlobalConfig as SharedGlobalConfig,
} from '@vercel/cli-config';

const TOKEN_STORAGE_ENV = 'VERCEL_TOKEN_STORAGE';
const KEYRING_UNAVAILABLE_ENV = 'VERCEL_TEST_KEYRING_UNAVAILABLE';
type RuntimeFlags = {
  keyringUnavailableForTesting: boolean;
};

type ResolvedCliAuthConfig = RuntimeFlags & {
  credStorage: CredStorage;
};

export type GlobalConfig = Pick<SharedGlobalConfig, 'credStorage'>;

export type Credentials = Omit<SharedAuthConfig, 'tokenSource'>;

type PersistableAuthConfig = SharedAuthConfig;

function parseCredentials(value: unknown): Credentials {
  const { tokenSource, ...credentials } = cliConfig.parseAuthConfig(value);
  return credentials;
}

function formatCredStorageError(value: unknown, source: string): string {
  try {
    cliConfig.parseGlobalConfig({ credStorage: value });
  } catch (error) {
    if (error instanceof Error) {
      return error.message.replace('`credStorage`', `\`${source}\``);
    }
  }

  return `Invalid value for \`${source}\`: ${JSON.stringify(
    value
  )}. Expected one of: ${cliConfig.CRED_STORAGE_CONFIG_VALUES.map(storage => JSON.stringify(storage)).join(', ')}.`;
}

function parseCredStorage(value: unknown, source: string): CredStorage {
  if (typeof value === 'undefined') {
    return cliConfig.DEFAULT_CRED_STORAGE;
  }

  try {
    const config = cliConfig.parseGlobalConfig({ credStorage: value });
    assert(
      config.credStorage !== undefined,
      'expected credStorage value to be non-empty'
    );
    return config.credStorage;
  } catch {
    throw new Error(formatCredStorageError(value, source));
  }
}

export function resolveCredStorage(value: unknown): CredStorage {
  return parseCredStorage(value, 'credStorage');
}

function readRuntimeFlags(): RuntimeFlags {
  return {
    keyringUnavailableForTesting: process.env[KEYRING_UNAVAILABLE_ENV] === '1',
  };
}

function resolveCliAuthConfig(
  dir: string,
  config?: GlobalConfig
): ResolvedCliAuthConfig {
  const runtimeFlags = readRuntimeFlags();

  if (config?.credStorage) {
    return {
      ...runtimeFlags,
      credStorage: resolveCredStorage(config.credStorage),
    };
  }

  const credStorageOverride = process.env[TOKEN_STORAGE_ENV];

  if (typeof credStorageOverride !== 'undefined') {
    return {
      ...runtimeFlags,
      credStorage: parseCredStorage(credStorageOverride, TOKEN_STORAGE_ENV),
    };
  }

  return {
    ...runtimeFlags,
    credStorage: resolveCredStorage(readGlobalConfig(dir).credStorage),
  };
}

export function readGlobalConfig(dir: string): GlobalConfig {
  const configPath = cliConfig.getConfigFilePath(dir);

  try {
    const config = cliConfig.readGlobalConfigFile(configPath);

    return {
      credStorage:
        typeof config.credStorage === 'undefined'
          ? undefined
          : resolveCredStorage(config.credStorage),
    };
  } catch (error) {
    if (isENOENTError(error)) {
      return {};
    }

    throw error;
  }
}

export function getCredStorage(
  dir: string,
  config?: GlobalConfig
): CredStorage {
  return resolveCliAuthConfig(dir, config).credStorage;
}

/** Return an account key suitable for use in keyrings for a given configPath.
 *
 *  `auth.json` and the keychain are supposed to be equivalent and exchangeable.
 * Since file-based credentials storage is configurable (via config path),
 * we must ensure that keyring entries are keyed by config path also.  We cannot
 * use the full path as the key, so use a 16-byte prefix of sha256 hash of
 * the path.
 */
function getKeyringAccount(configPath: string): string {
  const digest = createHash('sha256').update(configPath).digest('hex');
  return `cli:${digest.slice(0, 16)}`;
}

function isENOENTError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
}

function createMissingCredentialsError(configPath: string): Error {
  const error = new Error(
    `ENOENT: no such file or directory, open '${configPath}'`
  );
  Object.assign(error, { code: 'ENOENT' });
  return error;
}

export function CredentialsStore(dir: string, _config: GlobalConfig = {}) {
  const configPath = cliConfig.getAuthConfigFilePath(dir);
  const profile = getKeyringAccount(configPath).replace("cli:", "cli-");
  return {
    configPath,
    get(): Credentials {
      const raw = readSession(profile);
      if (raw === null) throw createMissingCredentialsError(configPath);
      return parseCredentials(JSON.parse(raw));
    },
    update(value: Partial<Credentials>): CredentialsStorageLocation | void {
      if (!value.skipWrite) writeSession(profile, JSON.stringify(parseCredentials(value)));
    },
    delete(): void { writeSession(profile, null); },
  };
}

export function readCredentials(dir: string, config: GlobalConfig = {}) {
  return CredentialsStore(dir, config).get();
}

export function readCliAuthConfig(dir: string, config: GlobalConfig = {}) {
  return readCredentials(dir, config);
}

export function writeCredentials(
  dir: string,
  credentials: Partial<Credentials>,
  config: GlobalConfig = {}
) {
  return CredentialsStore(dir, config).update(credentials);
}

function toPersistedAuthConfig(authConfig: PersistableAuthConfig): Credentials {
  const { skipWrite, tokenSource, ...persistedAuthConfig } = authConfig;
  return persistedAuthConfig;
}

export function persistCliAuthConfig(
  dir: string,
  authConfig: PersistableAuthConfig,
  config: GlobalConfig = {}
) {
  if (authConfig.skipWrite) {
    return;
  }

  const persistedAuthConfig = toPersistedAuthConfig(authConfig);

  if (!cliConfig.authConfigHasUsableTokenData(persistedAuthConfig)) {
    clearAllCredentialsStrict(dir);
    return;
  }

  return writeCredentials(dir, persistedAuthConfig, config);
}

export function clearCredentials(dir: string, config: GlobalConfig = {}) {
  CredentialsStore(dir, config).delete();
}

export function clearAllCredentials(dir: string) {
  clearCredentials(dir);
}

export function clearAllCredentialsStrict(dir: string) {
  clearCredentials(dir);
}
