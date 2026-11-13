/**
 * Airlock's own quarantine fetch, for a DSH without the install-gate hook: `pnpm add <spec> --ignore-scripts` in an
 * empty directory, with the profile's `.npmrc` as user config so registry and authentication settings match the real
 * installation, and an environment without credentials. With the hook, the plugin manager supplies the same fetch.
 */
import { existsSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { execa } from 'execa'
import type { PnpmInvocation, QuarantineFetchResult } from './dsh.ts'

/** Variable names never passed to pnpm: anything that looks like a credential, and DSH's own settings. */
const SENSITIVE = /KEY|PASSWORD|SECRET|TOKEN/i

/** Output kept for the report when a fetch fails. */
const OUTPUT_BYTES = 64 * 1024

/** What one fetch needs. */
export interface FetchOptions {
  readonly invocation: PnpmInvocation
  readonly profileDir: string
  /** The directory relative path specs are anchored to, as for the profile's own installation. */
  readonly cwd: string
  readonly spec: string
  readonly registry: string | null
  readonly timeoutMs: number
  readonly onOutput: (text: string, stream: 'stdout' | 'stderr') => void
}

/**
 * Anchor a relative path spec (`./x`, `file:../x`, `link:./x`) to a directory.
 * @param spec Installation spec.
 * @param cwd Anchor directory.
 * @returns The spec with an absolute path, or the spec unchanged.
 */
export function anchorPathSpec(spec: string, cwd: string): string {
  const match = /^(?<prefix>(?:file|link):)?(?<path>\.{1,2}(?:[/\\].*)?)$/.exec(spec)
  if (match?.groups?.path === undefined) return spec
  return `${match.groups.prefix ?? ''}${resolve(cwd, match.groups.path)}`
}

/** The parent environment without credentials or DSH settings. */
function scrubbedEnv(): Record<string, string> {
  const env: Record<string, string> = {}
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !SENSITIVE.test(key) && !key.toUpperCase().startsWith('DSH_')) env[key] = value
  }
  return env
}

/**
 * Fetch a spec into a quarantine directory holding a `package.json`, with lifecycle scripts disabled. A local
 * directory is installed as `file:` so pnpm resolves and locks what it depends on, and its own directory is scanned.
 * @param dir Quarantine directory.
 * @param signal Cancellation.
 * @param options pnpm invocation, spec, registry and bounds.
 * @returns Exit code, output tail, and the package directory of a local spec.
 */
export async function quarantineFetch(dir: string, signal: AbortSignal, options: FetchOptions): Promise<QuarantineFetchResult> {
  const npmrc = join(options.profileDir, '.npmrc')
  const env = {
    ...scrubbedEnv(), ...options.invocation.env,
    ...existsSync(npmrc) ? { npm_config_userconfig: npmrc } : {},
  }
  const anchored = anchorPathSpec(options.spec, options.cwd)
  const path = anchored.replace(/^(?:file|link):/, '')
  const local = isAbsolute(path) && !/\.(?:tgz|tar\.gz)$/.test(path)
  const child = execa(options.invocation.command, [
    ...options.invocation.args, 'add', local ? `file:${path}` : anchored, '--ignore-scripts', '--config.side-effects-cache=false',
    ...options.registry === null ? [] : [`--registry=${options.registry}`],
  ], {
    cwd: dir, env, extendEnv: false, reject: false, stdin: 'ignore', all: true, buffer: true,
    cancelSignal: signal, timeout: options.timeoutMs,
  })
  child.stdout.on('data', (chunk: Buffer) => { options.onOutput(chunk.toString('utf8'), 'stdout') })
  child.stderr.on('data', (chunk: Buffer) => { options.onOutput(chunk.toString('utf8'), 'stderr') })
  const settled = await child
  const all = Buffer.from(typeof settled.all === 'string' ? settled.all : '')
  return {
    exitCode: settled.exitCode ?? null,
    output: all.subarray(Math.max(0, all.length - OUTPUT_BYTES)).toString('utf8'),
    ...local ? { packageDir: path } : {},
  }
}
