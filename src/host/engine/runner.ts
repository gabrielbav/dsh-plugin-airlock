/** Scanner process execution with a minimal, explicit environment. */
import { constants } from 'node:fs'
import { access } from 'node:fs/promises'
import { homedir } from 'node:os'
import { delimiter, isAbsolute, join } from 'node:path'
import { execa } from 'execa'

/** One scanner invocation. */
export interface RunSpec {
  readonly argv: readonly string[]
  readonly cwd: string
  readonly timeoutMs: number
  /** Variables added to the base environment, such as an LLM key the configuration names. */
  readonly env: Readonly<Record<string, string>>
  readonly signal: AbortSignal
}

/** How a scanner process ended. */
export interface RunResult {
  readonly exitCode: number | null
  readonly stdout: string
  readonly stderr: string
  readonly timedOut: boolean
}

/** Variables every scanner keeps: tool caches and locale, never credentials. */
const BASE_ENV = ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'USER', 'XDG_CACHE_HOME', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy']

/**
 * Expand a leading `~` to the home directory.
 * @param path Configured path.
 * @returns The absolute path.
 */
export function expandHome(path: string): string {
  return path === '~' ? homedir() : path.startsWith('~/') ? join(homedir(), path.slice(2)) : path
}

/**
 * Find an executable on the configured search paths, then `PATH`.
 * @param command Name or absolute path.
 * @param searchPaths Directories searched first.
 * @returns The absolute path, or undefined when none is executable.
 */
export async function resolveExecutable(command: string, searchPaths: readonly string[]): Promise<string | undefined> {
  const candidates = isAbsolute(command)
    ? [command]
    : [...searchPaths.map(expandHome), ...(process.env.PATH ?? '').split(delimiter)].filter(dir => dir !== '').map(dir => join(dir, command))
  for (const candidate of candidates) {
    try {
      await access(candidate, constants.X_OK)
      return candidate
    } catch (error) {
      // ENOENT or EACCES: this candidate is not usable; the next one is tried.
      void error
    }
  }
  return undefined
}

/**
 * The environment scanners run with: a fixed allowlist of the Host's variables, the search paths prepended to `PATH`,
 * and the extra variables the call names.
 * @param searchPaths Directories prepended to `PATH`.
 * @param extra Explicit additions.
 * @returns The environment.
 */
export function scannerEnv(searchPaths: readonly string[], extra: Readonly<Record<string, string>>): Record<string, string> {
  const env: Record<string, string> = {}
  for (const name of BASE_ENV) {
    const value = process.env[name]
    if (value !== undefined) env[name] = value
  }
  env.PATH = [...searchPaths.map(expandHome), env.PATH ?? ''].filter(part => part !== '').join(delimiter)
  return { ...env, ...extra }
}

/**
 * Run one scanner to completion; never rejects for a non-zero exit, a timeout or a spawn failure.
 * @param spec The invocation; `argv[0]` is an absolute executable path.
 * @param searchPaths Directories prepended to `PATH` for helper executables the scanner starts.
 * @returns Exit status and captured output.
 */
export async function runScanner(spec: RunSpec, searchPaths: readonly string[]): Promise<RunResult> {
  const [file, ...args] = spec.argv
  if (file === undefined) throw new Error('airlock: empty scanner argv')
  const result = await execa(file, args, {
    cwd: spec.cwd, env: scannerEnv(searchPaths, spec.env), extendEnv: false, reject: false, stdin: 'ignore',
    timeout: spec.timeoutMs, cancelSignal: spec.signal, maxBuffer: 64 * 1024 * 1024,
  })
  return {
    exitCode: result.exitCode ?? null,
    stdout: typeof result.stdout === 'string' ? result.stdout : '',
    stderr: typeof result.stderr === 'string' ? result.stderr : '',
    timedOut: result.timedOut === true,
  }
}
