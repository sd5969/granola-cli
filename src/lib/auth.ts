import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { homedir, platform, release } from 'node:os';
import { join } from 'node:path';
import { deletePassword, getPassword, setPassword } from 'cross-keychain';
import type { Credentials } from '../types.js';
import { createGranolaDebug } from './debug.js';
import { withLock } from './lock.js';

const debug = createGranolaDebug('lib:auth');

const SERVICE_NAME = 'com.granola.cli';
const ACCOUNT_NAME = 'credentials';
const DEFAULT_CLIENT_ID = 'client_GranolaMac';

export async function getCredentials(): Promise<Credentials | null> {
  debug('loading credentials from keychain');
  try {
    const stored = await getPassword(SERVICE_NAME, ACCOUNT_NAME);
    if (!stored) {
      debug('no credentials found in keychain');
      return null;
    }

    const parsed = JSON.parse(stored);
    debug('credentials loaded, hasAccessToken: %s', Boolean(parsed.accessToken));
    return {
      refreshToken: parsed.refreshToken,
      accessToken: parsed.accessToken || '',
      clientId: parsed.clientId,
    };
  } catch (error) {
    debug('failed to get credentials: %O', error);
    return null;
  }
}

export async function saveCredentials(creds: Credentials): Promise<void> {
  debug('saving credentials to keychain');
  await setPassword(SERVICE_NAME, ACCOUNT_NAME, JSON.stringify(creds));
  debug('credentials saved');
}

export async function deleteCredentials(): Promise<void> {
  debug('deleting credentials from keychain');
  await deletePassword(SERVICE_NAME, ACCOUNT_NAME);
  debug('credentials deleted');
}

const GRANOLA_REFRESH_URL = 'https://api.granola.ai/v1/refresh-access-token';
const APP_VERSION = '7.0.0';

function getPackageVersion(): string {
  for (const path of ['../package.json', '../../package.json']) {
    try {
      const pkg = JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf-8'));
      return pkg.version;
    } catch {}
  }
  return '0.0.0';
}

const cliVersion = getPackageVersion();

function getRefreshClientHeaders(): Record<string, string> {
  const osPlatform = process.platform === 'darwin' ? 'macOS' : process.platform;
  return {
    'X-App-Version': APP_VERSION,
    'X-Client-Version': APP_VERSION,
    'X-Client-Type': 'cli',
    'X-Client-Platform': process.platform,
    'X-Client-Architecture': process.arch,
    'X-Client-Id': `granola-cli-${cliVersion}`,
    'User-Agent': `Granola/${APP_VERSION} granola-cli/${cliVersion} (${osPlatform} ${release()})`,
  };
}

export async function refreshAccessToken(): Promise<Credentials | null> {
  debug('attempting token refresh');

  try {
    return await withLock(async () => {
      const creds = await getCredentials();
      if (!creds?.refreshToken) {
        debug('cannot refresh: missing refreshToken');
        return null;
      }

      const response = await fetch(GRANOLA_REFRESH_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getRefreshClientHeaders(),
        },
        body: JSON.stringify({
          refresh_token: creds.refreshToken,
        }),
      });

      if (!response.ok) {
        debug('token refresh failed: %d %s', response.status, response.statusText);
        return null;
      }

      const data = (await response.json()) as { refresh_token: string; access_token: string };
      const newCreds: Credentials = {
        refreshToken: data.refresh_token,
        accessToken: data.access_token,
        clientId: creds.clientId,
      };

      await saveCredentials(newCreds);
      debug('token refresh successful, new credentials saved');
      return newCreds;
    });
  } catch (error) {
    debug('token refresh error: %O', error);
    return null;
  }
}

export function parseSupabaseJson(json: string): Credentials | null {
  debug('parsing supabase.json');
  try {
    const parsed = JSON.parse(json);

    // Try WorkOS tokens first (newer auth system)
    if (parsed.workos_tokens && typeof parsed.workos_tokens === 'string') {
      const workosTokens = JSON.parse(parsed.workos_tokens);
      if (workosTokens.access_token) {
        debug('found WorkOS tokens');
        return {
          refreshToken: workosTokens.refresh_token || '',
          accessToken: workosTokens.access_token,
          clientId: workosTokens.client_id || DEFAULT_CLIENT_ID,
        };
      }
    }

    // Fall back to Cognito tokens
    if (parsed.cognito_tokens && typeof parsed.cognito_tokens === 'string') {
      const cognitoTokens = JSON.parse(parsed.cognito_tokens);
      if (!cognitoTokens.refresh_token) return null;

      debug('found Cognito tokens');
      return {
        refreshToken: cognitoTokens.refresh_token,
        accessToken: cognitoTokens.access_token || '',
        clientId: cognitoTokens.client_id || DEFAULT_CLIENT_ID,
      };
    }

    // Legacy format: refresh_token at root level
    if (!parsed.refresh_token) return null;

    debug('found legacy token format');
    return {
      refreshToken: parsed.refresh_token,
      accessToken: parsed.access_token || '',
      clientId: parsed.client_id || DEFAULT_CLIENT_ID,
    };
  } catch (error) {
    debug('failed to parse supabase.json: %O', error);
    return null;
  }
}

/**
 * Gets the default path to the Granola supabase.json file based on the OS.
 *
 * @returns The platform-specific path to supabase.json
 */
export function getDefaultSupabasePath(): string {
  const home = homedir();
  const os = platform();

  let path: string;
  switch (os) {
    case 'darwin':
      path = join(home, 'Library', 'Application Support', 'Granola', 'supabase.json');
      break;
    case 'win32':
      path = join(
        process.env.APPDATA || join(home, 'AppData', 'Roaming'),
        'Granola',
        'supabase.json',
      );
      break;
    default:
      // Linux and other Unix-like systems
      path = join(home, '.config', 'granola', 'supabase.json');
  }
  debug('platform: %s, supabase path: %s', os, path);
  return path;
}

/**
 * Loads credentials from the default Granola supabase.json file.
 *
 * @returns Credentials if found and valid, null otherwise
 */
export async function loadCredentialsFromFile(): Promise<Credentials | null> {
  const path = getDefaultSupabasePath();
  debug('loading credentials from file: %s', path);
  try {
    const content = await readFile(path, 'utf-8');
    debug('file read successful, parsing content');
    return parseSupabaseJson(content);
  } catch (error) {
    debug('failed to load credentials from file: %O', error);
    return null;
  }
}
