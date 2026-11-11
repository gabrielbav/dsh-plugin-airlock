/**
 * Airlock's scan engine: fetch a spec into a quarantine directory with lifecycle scripts disabled, copy the package
 * files out, inventory them, run every scanner, and rule on the result. It loads no package code and starts no MCP
 * server.
 */
import { readFileSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { QuarantineFetchResult, InstallGateReport } from '../dsh.ts'
import type { AirlockConfig, ResolvedScanner, ScannerOutcome } from '../types.ts'
import { copySubject, digestTree, inventory, LOCAL_SKIPPED_DIRS } from './quarantine.ts'
import { resolveExecutable } from './runner.ts'
import { rule } from './score.ts'
import { REASON_TEXT } from '../reasons.ts'

/** The gate id the plugin manager knows Airlock by. */
export const GATE_ID = 'dsh-plugin-airlock'

export { digestTree } from './quarantine.ts'
export { rule, atLeast, SEVERITIES } from './score.ts'
export { resolveExecutable } from './runner.ts'

/** One scan request. */
export interface ScanRequest {
  readonly spec: string
  /** Install the spec into a directory holding a `package.json`, with lifecycle scripts disabled. */
  readonly fetch: (dir: string, signal: AbortSignal) => Promise<QuarantineFetchResult>
  readonly log: (text: string, stream: 'stdout' | 'stderr') => void
  readonly signal: AbortSignal
  readonly config: AirlockConfig
  /** Every scanner to run, in report order. */
  readonly scanners: readonly ResolvedScanner[]
  /** Parent of the quarantine directory; the system temporary directory when absent. */
  readonly tmpRoot?: string
}

/** A finished scan. */
export interface ScanResult {
  readonly report: InstallGateReport
  /**
   * Whether a directory holds exactly the scanned files.
   * @param dir Installed package directory.
   * @returns True when the digests match.
   */
  readonly verifyInstalled: (dir: string) => Promise<boolean>
  /** Remove the quarantine directory. */
  readonly dispose: () => Promise<void>
}

/**
 * Resolve the executables of scanners that name a command.
 * @param scanners Scanners to resolve.
 * @param searchPaths Directories searched before `PATH`.
 * @returns Each scanner id's executable, or null when it is missing, disabled, or names no command.
 */
export async function scannerAvailability(scanners: readonly ResolvedScanner[], searchPaths: readonly string[]): Promise<Map<string, string | null>> {
  const entries = await Promise.all(scanners.map(async scanner => [scanner.id,
    scanner.enabled && scanner.command !== undefined ? await resolveExecutable(scanner.command, searchPaths) ?? null : null] as const))
  return new Map(entries)
}

/**
 * Quarantine and scan one spec.
 * @param request The spec, fetch facility and configuration.
 * @returns The report with the means to verify the later installation; the caller disposes it.
 * @throws {Error} When the quarantine fetch fails; the real installation would fail the same way.
 */
export async function scanPackage(request: ScanRequest): Promise<ScanResult> {
  const root = await mkdtemp(join(request.tmpRoot ?? tmpdir(), 'dsh-airlock-'))
  const dispose = (): Promise<void> => rm(root, { recursive: true, force: true })
  try {
    const fetchDir = join(root, 'fetch')
    const subject = join(root, 'subject')
    const promptsRoot = join(root, 'prompts')
    const outDir = join(root, 'out')
    for (const dir of [fetchDir, subject, promptsRoot, outDir]) await mkdir(dir, { recursive: true })
    await writeFile(join(fetchDir, 'package.json'), '{"name":"dsh-airlock-quarantine","private":true}\n')
    request.log(`airlock: fetching ${request.spec} into quarantine with install scripts disabled\n`, 'stdout')
    const fetched = await request.fetch(fetchDir, request.signal)
    if (fetched.exitCode !== 0) throw new Error(`airlock: the quarantine fetch failed (exit ${fetched.exitCode ?? 'signal'})\n${fetched.output}`)
    const manifest: { dependencies?: Record<string, string> } = JSON.parse(await readFile(join(fetchDir, 'package.json'), 'utf8'))
    const names = Object.keys(manifest.dependencies ?? {})
    const name = names[0]
    if (names.length !== 1 || name === undefined) throw new Error(`airlock: the quarantine fetch added ${names.length} packages instead of one`)
    const fetchedDir = fetched.packageDir ?? await realpath(join(fetchDir, 'node_modules', name))
    const skipped: ReadonlySet<string> = fetched.packageDir === undefined ? new Set() : LOCAL_SKIPPED_DIRS
    const symlinks = await copySubject(fetchedDir, subject, skipped)
    // The digest leaves out nested node_modules and .git on both sides: the profile's hoisted layout can nest
    // dependencies inside the installed package that the quarantine resolved elsewhere.
    const digest = await digestTree(subject, LOCAL_SKIPPED_DIRS)
    let version: string | undefined
    try { version = (JSON.parse(readFileSync(join(subject, 'package.json'), 'utf8')) as { version?: string }).version }
    catch (error) { void error } // A package without a readable manifest reports no version; the manager rejects it later.
    const found = await inventory(subject, promptsRoot, request.config)
    request.log(`airlock: ${name}${version === undefined ? '' : `@${version}`}: ${found.skills.length} skill(s), ${found.prompts.length} prompt(s), ${found.mcpTools} MCP tool(s)\n`, 'stdout')
    const available = await scannerAvailability(request.scanners, request.config.searchPaths)
    const outcomes: ScannerOutcome[] = await Promise.all(request.scanners.map(async (scanner): Promise<ScannerOutcome> => {
      const { id } = scanner
      if (!scanner.enabled) return { id, status: 'disabled', findings: [], durationMs: 0, usedLlm: false }
      const executable = available.get(id) ?? null
      if (scanner.command !== undefined && executable === null) {
        return { id, status: 'unavailable', findings: [], detail: `${scanner.command} was not found`, durationMs: 0, usedLlm: false }
      }
      let outcome: ScannerOutcome
      try {
        outcome = await scanner.run({ subject, promptsRoot, fetchDir, outDir, inventory: found, config: request.config, signal: request.signal, executable: executable ?? '' })
        // An adapter reports under its own id, whatever it returned.
        outcome = { ...outcome, id }
      } catch (error) {
        outcome = { id, status: 'error', findings: [], detail: error instanceof Error ? error.message.slice(0, 300) : String(error), durationMs: 0, usedLlm: false }
      }
      request.log(`airlock: ${id}: ${outcome.status}${outcome.findings.length === 0 ? '' : ` (${outcome.findings.length})`}\n`, outcome.status === 'error' ? 'stderr' : 'stdout')
      return outcome
    }))
    request.signal.throwIfAborted()
    const extra = [...found.configFindings, ...symlinks.map(link => ({
      source: 'airlock', severity: 'low' as const, category: 'symlink', title: 'Symbolic link was not scanned', file: link, dependency: false, dedupeKey: `symlink:${link}`,
    }))]
    const ruling = rule([...outcomes, { id: 'airlock', status: 'clean', findings: extra, durationMs: 0, usedLlm: false }], request.config.policy)
    const kept = ruling.findings.slice(0, request.config.maxFindings)
    const report: InstallGateReport = {
      digest, spec: request.spec, packageName: name, ...version === undefined ? {} : { version },
      score: ruling.score, level: ruling.level, reasons: ruling.reasons.map(reason => REASON_TEXT[reason]),
      checks: outcomes.map(({ id, status, findings, detail, durationMs }) => ({
        id, name: request.scanners.find(scanner => scanner.id === id)?.name ?? id, status, findings: findings.length,
        ...detail === undefined ? {} : { detail }, durationMs,
      })),
      findings: kept.map(({ dependency, dedupeKey, ...finding }) => { void dependency; void dedupeKey; return finding }),
      omittedFindings: ruling.findings.length - kept.length,
      metrics: { skills: found.skills.length, prompts: found.prompts.length, mcpTools: found.mcpTools, dependencies: countLocked(fetchDir) },
      gates: [GATE_ID],
      checkedAt: new Date().toISOString(),
    }
    request.log(`airlock: security score ${report.score}/100, ${report.level}\n`, report.level === 'pass' ? 'stdout' : 'stderr')
    return { report, verifyInstalled: async dir => await digestTree(dir, LOCAL_SKIPPED_DIRS) === digest, dispose }
  } catch (error) {
    await dispose()
    throw error
  }
}

/** Count packages pinned in the quarantine lockfile. */
function countLocked(fetchDir: string): number {
  let text: string
  try { text = readFileSync(join(fetchDir, 'pnpm-lock.yaml'), 'utf8') }
  catch (error) { void error; return 0 } // No lockfile: no dependency was pinned.
  const packages = /^packages:\n([\s\S]*?)(?:^\S|(?![\s\S]))/m.exec(text)?.[1] ?? ''
  return packages.split('\n').filter(line => /^ {2}\S.*:$/.test(line)).length
}
