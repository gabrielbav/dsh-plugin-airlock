/**
 * Adapters from each scanner's command line and JSON report to normalized findings. Every adapter fails closed: an
 * exit status or report it does not recognize is an `error`, never `clean`.
 */
import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { join, relative } from 'node:path'
import type { SecuritySeverity } from '../dsh.ts'
import type { AirlockConfig, BuiltinScannerId, CustomScanner, ScanContext, ScannedFinding, ScannerOutcome } from '../types.ts'
import { runScanner, type RunResult } from './runner.ts'

const TEXT_LIMIT = 300

function clip(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim()
  return flat.length > TEXT_LIMIT ? `${flat.slice(0, TEXT_LIMIT - 1)}…` : flat
}

/**
 * Map a scanner's severity word to the normalized scale; unknown words read as `medium` so they still need review.
 * @param value Scanner severity.
 * @returns Normalized severity.
 */
export function severityOf(value: unknown): SecuritySeverity {
  switch (String(value).toLowerCase()) {
    case 'critical': return 'critical'
    case 'high': return 'high'
    case 'medium': case 'moderate': return 'medium'
    case 'low': return 'low'
    case 'info': case 'informational': case 'safe': case 'none': return 'info'
    default: return 'medium'
  }
}

/**
 * Map a CVSS score string to the normalized scale.
 * @param score OSV `max_severity`, such as `7.5`; empty when the advisory has none.
 * @returns Normalized severity; an advisory without a score reads as `medium`.
 */
export function cvssSeverity(score: string | undefined): SecuritySeverity {
  const value = Number.parseFloat(score ?? '')
  if (Number.isNaN(value)) return 'medium'
  return value >= 9 ? 'critical' : value >= 7 ? 'high' : value >= 4 ? 'medium' : value > 0 ? 'low' : 'info'
}

function failed(id: string, run: RunResult, started: number, what: string): ScannerOutcome {
  const reason = run.timedOut ? 'timed out' : `exited with ${run.exitCode ?? 'a signal'}`
  return { id, status: 'error', findings: [], detail: clip(`${what} ${reason}: ${run.stderr || run.stdout}`), durationMs: Date.now() - started, usedLlm: false }
}

function settled(id: string, findings: ScannedFinding[], started: number, usedLlm: boolean): ScannerOutcome {
  return { id, status: findings.length === 0 ? 'clean' : 'findings', findings, durationMs: Date.now() - started, usedLlm }
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, 'utf8'))
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? Object.fromEntries(Object.entries(value)) : {}
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined
}

function llmEnv(config: AirlockConfig, prefix: 'SKILL_SCANNER_LLM' | 'MCP_SCANNER_LLM'): Record<string, string> | undefined {
  if (!config.llm.enabled) return undefined
  const key = process.env[config.llm.apiKeyEnv]
  if (key === undefined || key === '') return undefined
  return {
    [`${prefix}_API_KEY`]: key,
    ...config.llm.model === '' ? {} : { [`${prefix}_MODEL`]: config.llm.model },
    ...config.llm.baseUrl === '' ? {} : { [`${prefix}_BASE_URL`]: config.llm.baseUrl },
    ...prefix === 'SKILL_SCANNER_LLM' ? { SKILL_SCANNER_LLM_PROVIDER: config.llm.provider } : {},
  }
}

/** Cisco Skill Scanner over the package's skills and the extracted prompts. */
async function ciscoSkillScanner(ctx: ScanContext): Promise<ScannerOutcome> {
  const started = Date.now()
  const roots = [
    ...ctx.inventory.skills.length > 0 ? [{ dir: ctx.subject, label: '' }] : [],
    ...ctx.inventory.prompts.length > 0 ? [{ dir: ctx.promptsRoot, label: 'prompts' }] : [],
  ]
  if (roots.length === 0) return { id: 'cisco-skill-scanner', status: 'not-applicable', findings: [], durationMs: 0, usedLlm: false }
  const env = llmEnv(ctx.config, 'SKILL_SCANNER_LLM')
  const findings: ScannedFinding[] = []
  for (const [index, root] of roots.entries()) {
    const out = join(ctx.outDir, `cisco-skill-scanner-${index}.json`)
    const run = await runScanner({
      argv: [ctx.executable, 'scan-all', root.dir, '--recursive', '--use-behavioral', ...env === undefined ? [] : ['--use-llm'], '--format', 'json', '--output', out],
      cwd: ctx.outDir, timeoutMs: ctx.config.scannerTimeoutMs, env: env ?? {}, signal: ctx.signal,
    }, ctx.config.searchPaths)
    if (run.timedOut || run.exitCode === null || run.exitCode > 1 || !existsSync(out)) return failed('cisco-skill-scanner', run, started, 'skill-scanner')
    const report = record(await readJson(out))
    for (const result of list(report.results)) {
      const skill = record(result)
      const skillPath = text(skill.skill_path) ?? root.dir
      const base = relative(root.dir, skillPath)
      for (const item of list(skill.findings)) {
        const finding = record(item)
        const file = [root.label, base, text(finding.file_path)].filter(part => part !== undefined && part !== '' && part !== '.').join('/')
        const line = typeof finding.line_number === 'number' ? finding.line_number : undefined
        const ruleId = text(finding.rule_id)
        findings.push({
          scanner: 'cisco-skill-scanner', severity: severityOf(finding.severity), category: text(finding.category) ?? 'unknown',
          title: clip(text(finding.title) ?? text(finding.description) ?? 'Finding'),
          ...ruleId === undefined ? {} : { ruleId }, ...file === '' ? {} : { file }, ...line === undefined ? {} : { line },
          dependency: false, dedupeKey: `cisco-skill:${file}:${ruleId ?? ''}:${line ?? ''}:${text(finding.title) ?? ''}`,
        })
      }
    }
  }
  return settled('cisco-skill-scanner', findings, started, env !== undefined)
}

/** SkillScan audit over each skill file and extracted prompt. */
async function skillscan(ctx: ScanContext): Promise<ScannerOutcome> {
  const started = Date.now()
  const files = [
    ...ctx.inventory.skills.map(dir => ({ path: join(ctx.subject, dir, 'SKILL.md'), label: dir === '.' ? 'SKILL.md' : `${dir}/SKILL.md` })),
    ...ctx.inventory.prompts.map(prompt => ({ path: join(ctx.promptsRoot, prompt.dir, 'SKILL.md'), label: prompt.source })),
  ]
  if (files.length === 0) return { id: 'skillscan', status: 'not-applicable', findings: [], durationMs: 0, usedLlm: false }
  const findings: ScannedFinding[] = []
  for (const file of files) {
    const run = await runScanner({
      argv: [ctx.executable, 'audit', file.path, '--format', 'json'],
      cwd: ctx.outDir, timeoutMs: ctx.config.scannerTimeoutMs, env: {}, signal: ctx.signal,
    }, ctx.config.searchPaths)
    // 0 passed and 1 failed the scanner's own threshold; both carry a report.
    if (run.timedOut || (run.exitCode !== 0 && run.exitCode !== 1)) return failed('skillscan', run, started, 'skillscan')
    let report: Record<string, unknown>
    try { report = record(JSON.parse(run.stdout)) }
    catch (error) { void error; return failed('skillscan', run, started, 'skillscan printed no JSON and') }
    for (const item of list(report.findings)) {
      const finding = record(item)
      const line = typeof finding.line === 'number' ? finding.line : undefined
      const message = text(finding.message) ?? 'Finding'
      findings.push({
        scanner: 'skillscan', severity: severityOf(finding.severity), category: text(finding.analyzer) ?? 'unknown',
        title: clip(message), file: file.label, ...line === undefined ? {} : { line },
        dependency: false, dedupeKey: `skillscan:${file.label}:${message}:${text(finding.evidence) ?? ''}`,
      })
    }
  }
  return settled('skillscan', findings, started, false)
}

/** Cisco MCP Scanner, static mode, over MCP tool definitions the package ships; it never starts a server. */
async function ciscoMcpScanner(ctx: ScanContext): Promise<ScannerOutcome> {
  const started = Date.now()
  if (ctx.inventory.mcpToolFiles.length === 0) return { id: 'cisco-mcp-scanner', status: 'not-applicable', findings: [], durationMs: 0, usedLlm: false }
  const env = llmEnv(ctx.config, 'MCP_SCANNER_LLM')
  const findings: ScannedFinding[] = []
  for (const file of ctx.inventory.mcpToolFiles) {
    const run = await runScanner({
      argv: [ctx.executable, '--analyzers', env === undefined ? 'yara' : 'yara,llm', '--raw', 'static', '--tools', join(ctx.subject, file)],
      cwd: ctx.outDir, timeoutMs: ctx.config.scannerTimeoutMs, env: env ?? {}, signal: ctx.signal,
    }, ctx.config.searchPaths)
    if (run.timedOut || run.exitCode !== 0) return failed('cisco-mcp-scanner', run, started, 'mcp-scanner')
    let results: unknown[]
    try { results = list(JSON.parse(run.stdout)) }
    catch (error) { void error; return failed('cisco-mcp-scanner', run, started, 'mcp-scanner printed no JSON and') }
    for (const item of results) {
      const result = record(item)
      if (result.status !== 'completed' || result.is_safe === null) {
        return { id: 'cisco-mcp-scanner', status: 'error', findings: [], detail: clip(`analysis of ${text(result.tool_name) ?? 'a tool'} did not complete`), durationMs: Date.now() - started, usedLlm: false }
      }
      for (const [analyzer, value] of Object.entries(record(result.findings))) {
        const analysis = record(value)
        if (severityOf(analysis.severity) === 'info') continue
        const tool = text(result.tool_name) ?? '?'
        const threats = list(analysis.threat_names).filter(name => typeof name === 'string').join(', ')
        findings.push({
          scanner: 'cisco-mcp-scanner', severity: severityOf(analysis.severity), category: threats === '' ? analyzer : threats.toLowerCase(),
          title: clip(`Tool "${tool}": ${text(analysis.threat_summary) ?? threats}`), ruleId: analyzer, file,
          dependency: false, dedupeKey: `mcp:${file}:${tool}:${analyzer}`,
        })
      }
    }
  }
  return settled('cisco-mcp-scanner', findings, started, env !== undefined)
}

/** OSV-Scanner over the quarantine lockfile, which pins every transitive dependency. */
async function osvScanner(ctx: ScanContext): Promise<ScannerOutcome> {
  const started = Date.now()
  const lockfile = join(ctx.fetchDir, 'pnpm-lock.yaml')
  if (!existsSync(lockfile)) return { id: 'osv-scanner', status: 'error', findings: [], detail: 'the quarantine fetch wrote no pnpm-lock.yaml', durationMs: 0, usedLlm: false }
  const run = await runScanner({
    argv: [ctx.executable, 'scan', 'source', '--format', 'json', '-L', lockfile],
    cwd: ctx.outDir, timeoutMs: ctx.config.scannerTimeoutMs, env: {}, signal: ctx.signal,
  }, ctx.config.searchPaths)
  // 128: the lockfile lists no packages, so there is nothing to look up.
  if (run.exitCode === 128) return { id: 'osv-scanner', status: 'not-applicable', findings: [], durationMs: Date.now() - started, usedLlm: false }
  if (run.timedOut || (run.exitCode !== 0 && run.exitCode !== 1)) return failed('osv-scanner', run, started, 'osv-scanner')
  let report: Record<string, unknown>
  try { report = record(JSON.parse(run.stdout)) }
  catch (error) { void error; return failed('osv-scanner', run, started, 'osv-scanner printed no JSON and') }
  const findings: ScannedFinding[] = []
  for (const result of list(report.results)) {
    for (const item of list(record(result).packages)) {
      const entry = record(item)
      const pkg = record(entry.package)
      const name = `${text(pkg.name) ?? '?'}@${text(pkg.version) ?? '?'}`
      const vulns = new Map(list(entry.vulnerabilities).map(value => { const vuln = record(value); return [text(vuln.id) ?? '', vuln] }))
      for (const value of list(entry.groups)) {
        const group = record(value)
        const ids = list(group.ids).filter((id): id is string => typeof id === 'string')
        const first = ids[0] ?? '?'
        const vuln = vulns.get(first) ?? {}
        const aliases = [...ids, ...list(group.aliases).filter((id): id is string => typeof id === 'string')]
        const cve = aliases.find(id => id.startsWith('CVE-')) ?? first
        findings.push({
          scanner: 'osv-scanner', severity: cvssSeverity(text(group.max_severity)), category: 'vulnerability',
          title: clip(`${name}: ${first}${text(vuln.summary) === undefined ? '' : ` ${text(vuln.summary)}`}`), ruleId: first,
          file: 'pnpm-lock.yaml', dependency: true, dedupeKey: `vuln:${name}:${cve}`,
        })
      }
    }
  }
  return settled('osv-scanner', findings, started, false)
}

/** Trivy: dependency vulnerabilities from the lockfile, and secrets and misconfigurations in the package files. */
async function trivy(ctx: ScanContext): Promise<ScannerOutcome> {
  const started = Date.now()
  const findings: ScannedFinding[] = []
  const runs = [
    { target: ctx.fetchDir, scanners: 'vuln', extra: ['--skip-dirs', 'node_modules'] },
    { target: ctx.subject, scanners: 'secret,misconfig', extra: [] },
  ]
  for (const pass of runs) {
    const run = await runScanner({
      argv: [ctx.executable, 'fs', '--scanners', pass.scanners, '--format', 'json', '--quiet', '--exit-code', '0', ...pass.extra, pass.target],
      cwd: ctx.outDir, timeoutMs: ctx.config.scannerTimeoutMs, env: {}, signal: ctx.signal,
    }, ctx.config.searchPaths)
    if (run.timedOut || run.exitCode !== 0) return failed('trivy', run, started, 'trivy')
    let report: Record<string, unknown>
    try { report = record(JSON.parse(run.stdout)) }
    catch (error) { void error; return failed('trivy', run, started, 'trivy printed no JSON and') }
    for (const value of list(report.Results)) {
      const result = record(value)
      const target = text(result.Target) ?? ''
      for (const item of list(result.Vulnerabilities)) {
        const vuln = record(item)
        const name = `${text(vuln.PkgName) ?? '?'}@${text(vuln.InstalledVersion) ?? '?'}`
        const id = text(vuln.VulnerabilityID) ?? '?'
        findings.push({
          scanner: 'trivy', severity: severityOf(vuln.Severity), category: 'vulnerability',
          title: clip(`${name}: ${id}${text(vuln.Title) === undefined ? '' : ` ${text(vuln.Title)}`}`), ruleId: id,
          file: 'pnpm-lock.yaml', dependency: true, dedupeKey: `vuln:${name}:${id}`,
        })
      }
      for (const item of list(result.Secrets)) {
        const secret = record(item)
        const line = typeof secret.StartLine === 'number' ? secret.StartLine : undefined
        const ruleId = text(secret.RuleID)
        findings.push({
          scanner: 'trivy', severity: severityOf(secret.Severity), category: 'secret',
          title: clip(`Embedded secret: ${text(secret.Title) ?? ruleId ?? 'credential'}`), ...ruleId === undefined ? {} : { ruleId },
          file: target, ...line === undefined ? {} : { line }, dependency: false, dedupeKey: `secret:${target}:${line ?? ''}`,
        })
      }
      for (const item of list(result.Misconfigurations)) {
        const misconfig = record(item)
        const id = text(misconfig.ID) ?? text(misconfig.AVDID)
        findings.push({
          scanner: 'trivy', severity: severityOf(misconfig.Severity), category: 'misconfiguration',
          title: clip(text(misconfig.Title) ?? text(misconfig.Message) ?? 'Misconfiguration'), ...id === undefined ? {} : { ruleId: id },
          file: target, dependency: false, dedupeKey: `misconfig:${target}:${id ?? ''}`,
        })
      }
    }
  }
  return settled('trivy', findings, started, false)
}

/** Gitleaks over the package files, with secrets redacted from its report. */
async function gitleaks(ctx: ScanContext): Promise<ScannerOutcome> {
  const started = Date.now()
  const out = join(ctx.outDir, 'gitleaks.json')
  // A distinct leak exit code separates findings from errors, which also exit 1.
  const run = await runScanner({
    argv: [ctx.executable, 'dir', ctx.subject, '--report-format', 'json', '--report-path', out, '--exit-code', '3', '--no-banner', '--redact'],
    cwd: ctx.outDir, timeoutMs: ctx.config.scannerTimeoutMs, env: {}, signal: ctx.signal,
  }, ctx.config.searchPaths)
  if (run.timedOut || (run.exitCode !== 0 && run.exitCode !== 3) || !existsSync(out)) return failed('gitleaks', run, started, 'gitleaks')
  const findings: ScannedFinding[] = []
  for (const item of list(await readJson(out))) {
    const leak = record(item)
    const file = relative(ctx.subject, text(leak.File) ?? '')
    const line = typeof leak.StartLine === 'number' ? leak.StartLine : undefined
    const ruleId = text(leak.RuleID)
    findings.push({
      scanner: 'gitleaks', severity: 'high', category: 'secret',
      title: clip(`Embedded secret: ${text(leak.Description) ?? ruleId ?? 'credential'}`), ...ruleId === undefined ? {} : { ruleId },
      file, ...line === undefined ? {} : { line }, dependency: false, dedupeKey: `secret:${file}:${line ?? ''}`,
    })
  }
  return settled('gitleaks', findings, started, false)
}

/** Every adapter by scanner id. */
export const SCANNERS: Readonly<Record<BuiltinScannerId, (ctx: ScanContext) => Promise<ScannerOutcome>>> = {
  'cisco-skill-scanner': ciscoSkillScanner,
  'skillscan': skillscan,
  'cisco-mcp-scanner': ciscoMcpScanner,
  'osv-scanner': osvScanner,
  'trivy': trivy,
  'gitleaks': gitleaks,
}

/** SARIF `level` to the normalized scale, used when a result carries no `security-severity`. */
const SARIF_LEVELS: Readonly<Record<string, SecuritySeverity>> = { error: 'high', warning: 'medium', note: 'low', none: 'info' }

/**
 * Read a SARIF 2.1 log into findings. Severity comes from the result's or its rule's `security-severity` (CVSS), else
 * from `level`; locations are taken relative to the scanned directory.
 * @param log Parsed SARIF document.
 * @param scanner Scanner id the findings carry.
 * @param base Scanned directory, to relativize absolute locations.
 * @param dependency Whether findings are dependency vulnerabilities.
 * @returns Findings, or undefined when the document is not SARIF.
 */
export function sarifFindings(log: unknown, scanner: string, base: string, dependency: boolean): ScannedFinding[] | undefined {
  const document = record(log)
  if (!Array.isArray(document.runs)) return undefined
  const findings: ScannedFinding[] = []
  for (const value of list(document.runs)) {
    const run = record(value)
    const rules = new Map(list(record(record(run.tool).driver).rules).map(item => { const rule = record(item); return [text(rule.id) ?? '', rule] }))
    for (const item of list(run.results)) {
      const result = record(item)
      const ruleId = text(result.ruleId)
      const rule = rules.get(ruleId ?? '') ?? {}
      const score = text(record(result.properties)['security-severity']) ?? text(record(rule.properties)['security-severity'])
        ?? (typeof record(rule.properties)['security-severity'] === 'number' ? String(record(rule.properties)['security-severity']) : undefined)
      const level = text(result.level) ?? text(record(rule.defaultConfiguration).level) ?? 'warning'
      const severity = score === undefined ? SARIF_LEVELS[level] ?? 'medium' : cvssSeverity(score)
      const physical = record(record(list(result.locations)[0]).physicalLocation)
      const uri = text(record(physical.artifactLocation).uri)
      const file = uri === undefined ? undefined : relative(base, uri.replace(/^file:\/\//, '').startsWith('/') ? uri.replace(/^file:\/\//, '') : join(base, uri))
      const line = typeof record(physical.region).startLine === 'number' ? Number(record(physical.region).startLine) : undefined
      const title = text(record(result.message).text) ?? text(record(rule.shortDescription).text) ?? ruleId ?? 'Finding'
      findings.push({
        scanner, severity, category: dependency ? 'vulnerability' : 'custom', title: clip(title),
        ...ruleId === undefined ? {} : { ruleId }, ...file === undefined ? {} : { file }, ...line === undefined ? {} : { line },
        dependency, dedupeKey: `${scanner}:${ruleId ?? ''}:${file ?? ''}:${line ?? ''}:${title}`,
      })
    }
  }
  return findings
}

/**
 * Build the adapter of a custom SARIF scanner from settings.
 * @param scanner The person's scanner definition.
 * @returns The scanner run.
 */
export function customScanner(scanner: CustomScanner): (ctx: ScanContext) => Promise<ScannerOutcome> {
  return async (ctx) => {
    const started = Date.now()
    const target = scanner.target === 'lockfile' ? ctx.fetchDir : ctx.subject
    const output = join(ctx.outDir, `${scanner.id}.sarif`)
    const writesFile = scanner.args.some(arg => arg.includes('{output}'))
    const argv = scanner.args.map(arg => arg.replaceAll('{target}', target).replaceAll('{output}', output))
    const run = await runScanner({ argv: [ctx.executable, ...argv], cwd: ctx.outDir, timeoutMs: ctx.config.scannerTimeoutMs, env: {}, signal: ctx.signal }, ctx.config.searchPaths)
    if (run.timedOut || run.exitCode === null || !scanner.okExitCodes.includes(run.exitCode)) return failed(scanner.id, run, started, scanner.name)
    let log: unknown
    try { log = JSON.parse(writesFile ? await readFile(output, 'utf8') : run.stdout) }
    catch (error) { void error; return failed(scanner.id, run, started, `${scanner.name} wrote no SARIF JSON and`) }
    const findings = sarifFindings(log, scanner.id, target, scanner.target === 'lockfile')
    if (findings === undefined) return failed(scanner.id, run, started, `${scanner.name} wrote JSON that is not SARIF and`)
    return settled(scanner.id, findings, started, false)
  }
}
