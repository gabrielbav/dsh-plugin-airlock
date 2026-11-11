import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { applySettings, ConfigError, Config, DEFAULT_CONFIG, parseConfig, parseSettings } from '../src/host/config.ts'
import { digestTree, rule, scanPackage } from '../src/host/engine/index.ts'
import { inventory } from '../src/host/engine/quarantine.ts'
import { customScanner, sarifFindings } from '../src/host/engine/scanners.ts'
import { REASON_TEXT } from '../src/host/reasons.ts'
import type { ResolvedScanner, ScannedFinding, ScannerOutcome } from '../src/host/types.ts'

const finding = (severity: ScannedFinding['severity'], dependency = false, key = `${severity}:${dependency}`): ScannedFinding => ({
  source: 'test', severity, category: 'test', title: 'test finding', dependency, dedupeKey: key,
})

const outcome = (findings: ScannedFinding[], extra: Partial<ScannerOutcome> = {}): ScannerOutcome => ({
  id: 'test', status: findings.length === 0 ? 'clean' : 'findings', findings, durationMs: 0, usedLlm: true, ...extra,
})

describe('rule', () => {
  const policy = DEFAULT_CONFIG.policy

  it('passes a clean scan that ran the LLM analyzers', () => {
    expect(rule([outcome([])], policy)).toEqual({ score: 100, level: 'pass', reasons: [], findings: [] })
  })

  it('blocks on one critical package finding whatever the other scanners report', () => {
    expect(rule([outcome([finding('critical')]), outcome([]), outcome([])], policy)).toMatchObject({ level: 'block', reasons: expect.arrayContaining(['finding-blocks']) })
  })

  it('reviews dependency vulnerabilities below the dependency block severity however many there are', () => {
    expect(rule([outcome([finding('high', true)])], policy)).toMatchObject({ level: 'review', score: 88 })
    expect(rule([outcome(Array.from({ length: 9 }, (_, i) => finding('high', true, `d${i}`)))], policy)).toMatchObject({ level: 'review', score: 0 })
    expect(rule([outcome([finding('critical', true)])], policy)).toMatchObject({ level: 'block' })
  })

  it('caps a clean scan at review without LLM analysis, a missing scanner, or a failed scanner', () => {
    expect(rule([outcome([], { usedLlm: false })], policy)).toMatchObject({ level: 'review', reasons: ['llm-not-run'] })
    expect(rule([outcome([], { usedLlm: false })], policy, false)).toMatchObject({ level: 'pass', reasons: [] })
    expect(rule([outcome([]), outcome([], { status: 'unavailable' })], policy)).toMatchObject({ level: 'review', reasons: ['scanner-unavailable'] })
    expect(rule([outcome([]), outcome([], { status: 'error' })], policy)).toMatchObject({ level: 'review', reasons: ['scanner-error'] })
  })

  it('counts a shared finding once, floors the score, and blocks below the block score', () => {
    const shared = finding('medium', false, 'same')
    expect(rule([outcome([shared]), outcome([shared])], policy).findings).toHaveLength(1)
    expect(rule([outcome(Array.from({ length: 12 }, (_, i) => finding('high', false, `h${i}`)))], policy).score).toBe(0)
    expect(rule([outcome(Array.from({ length: 7 }, (_, i) => finding('medium', false, `m${i}`)))], policy)).toMatchObject({ score: 30, level: 'block' })
  })
})

describe('settings', () => {
  it('validates settings and refuses unknown fields, bad severities and reserved custom ids', () => {
    expect(parseSettings({ policy: { requireLlm: false }, scanners: { trivy: { enabled: false } } }))
      .toMatchObject({ policy: { requireLlm: false }, scanners: { trivy: { enabled: false } } })
    expect(() => parseSettings({ polcy: {} })).toThrow(ConfigError)
    expect(() => parseSettings({ policy: { blockSeverity: 'severe' } })).toThrow(/blockSeverity/)
    expect(() => parseSettings({ custom: [{ id: 'trivy', command: 'x' }] })).toThrow(/built-in/)
    expect(() => parseSettings({ custom: [{ id: 'a', command: 'x' }, { id: 'a', command: 'y' }] })).toThrow(/duplicate/)
  })

  it('applies settings over the row config and keeps the block score at or below the pass score', () => {
    const config = parseConfig({ policy: { passScore: 90 } })
    expect(applySettings(config, { policy: { blockScore: 50 } }).policy).toMatchObject({ passScore: 90, blockScore: 50 })
    expect(() => applySettings(config, { policy: { blockScore: 95 } })).toThrow(/must not exceed/)
  })

  it('reports invalid row config as Standard Schema issues', () => {
    expect(Config['~standard'].validate({ scannerTimeoutMs: 5 })).toMatchObject({ issues: [{ path: ['scannerTimeoutMs'] }] })
    expect(Config['~standard'].validate(undefined)).toMatchObject({ value: { maxFindings: 200 } })
  })
})

describe('quarantine and scanners', () => {
  let root: string
  beforeEach(async () => { root = await mkdtemp(join(tmpdir(), 'airlock-spec-')) })
  afterEach(async () => { await rm(root, { recursive: true, force: true }) })

  it('inventories skills, subagent prompts, MCP tools, MCP servers and !!js configuration', async () => {
    const subject = join(root, 'subject')
    await mkdir(join(subject, 'skills', 'a'), { recursive: true })
    await writeFile(join(subject, 'skills', 'a', 'SKILL.md'), '---\nname: a\ndescription: a\n---\nhello\n')
    await writeFile(join(subject, 'tools.json'), JSON.stringify({ tools: [{ name: 'x', description: 'y', inputSchema: {} }] }))
    await writeFile(join(subject, 'cordis.patch.yml'), [
      '- insert:', '    - id: preset', '      name: p', '      disabled: !!js "false"', '      config:',
      `        prefix: ${'You are an agent that helps. '.repeat(4)}`,
      '    - id: mcp', '      name: m', '      config:', '        servers:', '          evil: { command: npx, args: [evil-server] }',
    ].join('\n'))
    const found = await inventory(subject, join(root, 'prompts'), { promptMinChars: 80, maxJsonBytes: 1 << 20 })
    expect(found).toMatchObject({ skills: ['skills/a'], mcpToolFiles: ['tools.json'], mcpTools: 1, prompts: [{ dir: 'prompt-1', source: 'cordis.patch.yml#preset' }] })
    expect(found.configFindings.map(item => item.ruleId).sort()).toEqual(['AIRLOCK_CONFIG_JS', 'AIRLOCK_MCP_SERVER'])
  })

  it('digests file contents, skipping node_modules only when asked', async () => {
    await writeFile(join(root, 'a.txt'), 'one')
    const skipped = new Set(['node_modules'])
    const before = await digestTree(root, skipped)
    const all = await digestTree(root)
    await mkdir(join(root, 'node_modules', 'x'), { recursive: true })
    await writeFile(join(root, 'node_modules', 'x', 'b.txt'), 'shipped')
    expect(await digestTree(root, skipped)).toBe(before)
    expect(await digestTree(root)).not.toBe(all)
  })

  it('reads SARIF severities from security-severity, then level, with relative locations', () => {
    const findings = sarifFindings({
      runs: [{
        tool: { driver: { rules: [{ id: 'R1', properties: { 'security-severity': '9.8' } }] } },
        results: [
          { ruleId: 'R1', message: { text: 'eval of input' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'src/a.js' }, region: { startLine: 3 } } }] },
          { ruleId: 'R2', level: 'note', message: { text: 'style' } },
        ],
      }],
    }, 'semgrep', '/pkg', false)
    expect(findings).toEqual([
      expect.objectContaining({ severity: 'critical', title: 'eval of input', file: 'src/a.js', line: 3, ruleId: 'R1' }),
      expect.objectContaining({ severity: 'low', title: 'style' }),
    ])
    expect(sarifFindings({ not: 'sarif' }, 'x', '/pkg', false)).toBeUndefined()
  })

  /** Scan a one-file package with the given scanners. */
  async function scan(scanners: ResolvedScanner[], requireLlm = false) {
    const pkg = join(root, 'pkg')
    await mkdir(pkg, { recursive: true })
    await writeFile(join(pkg, 'package.json'), '{"name":"pkg","version":"1.0.0"}')
    return scanPackage({
      spec: pkg, signal: new AbortController().signal, log: () => {}, tmpRoot: root, scanners,
      config: applySettings(DEFAULT_CONFIG, { policy: { requireLlm } }),
      fetch: async (dir) => {
        await mkdir(join(dir, 'node_modules'), { recursive: true })
        await writeFile(join(dir, 'package.json'), '{"dependencies":{"pkg":"file:x"}}')
        return { exitCode: 0, output: '', packageDir: pkg }
      },
    })
  }

  it('runs a custom SARIF scanner and fails closed on an unrecognized exit status', async () => {
    const bin = join(root, 'bin')
    await mkdir(bin)
    const tool = join(bin, 'fake-sarif')
    await writeFile(tool, `#!/bin/sh\nprintf '%s' '{"runs":[{"results":[{"ruleId":"X","level":"error","message":{"text":"bad thing"}}]}]}' > "$2"\nexit 0\n`)
    await chmod(tool, 0o755)
    const failing = join(bin, 'failing')
    await writeFile(failing, '#!/bin/sh\necho boom >&2\nexit 7\n')
    await chmod(failing, 0o755)
    const custom = (id: string, command: string): ResolvedScanner => ({
      id, name: id, origin: 'custom', enabled: true, command,
      run: customScanner({ id, name: id, enabled: true, command, args: ['{target}', '{output}'], target: 'package', okExitCodes: [0, 1] }),
    })
    const scanned = await scan([custom('fake', tool), custom('broken', failing)])
    try {
      expect(scanned.report.checks).toEqual([
        expect.objectContaining({ id: 'fake', status: 'findings', findings: 1 }),
        expect.objectContaining({ id: 'broken', status: 'error' }),
      ])
      expect(scanned.report).toMatchObject({ level: 'review', score: 75, findings: [expect.objectContaining({ source: 'fake', severity: 'high', title: 'bad thing' })] })
      expect(scanned.report.reasons).toEqual(expect.arrayContaining([REASON_TEXT['scanner-error'], REASON_TEXT['score-below-pass']]))
      expect(scanned.report).toMatchObject({ gates: ['dsh-plugin-airlock'], metrics: { skills: 0 } })
    } finally { await scanned.dispose() }
  })

  it('runs a plugin scanner in-process, reports a missing command as unavailable, and verifies installed files', async () => {
    const scanned = await scan([
      { id: 'inline', name: 'Inline', origin: 'plugin', enabled: true, command: undefined, run: async () => outcome([]) },
      { id: 'absent', name: 'Absent', origin: 'plugin', enabled: true, command: 'definitely-not-installed-tool', run: async () => outcome([]) },
    ])
    try {
      expect(scanned.report.checks.map(item => [item.id, item.status])).toEqual([['inline', 'clean'], ['absent', 'unavailable']])
      expect(scanned.report.level).toBe('review')
      expect(await scanned.verifyInstalled(join(root, 'pkg'))).toBe(true)
      await writeFile(join(root, 'pkg', 'extra.js'), 'tampered')
      expect(await scanned.verifyInstalled(join(root, 'pkg'))).toBe(false)
    } finally { await scanned.dispose() }
  })

  it('refuses when the quarantine fetch fails', async () => {
    await expect(scanPackage({
      spec: 'x', signal: new AbortController().signal, log: () => {}, tmpRoot: root, config: DEFAULT_CONFIG, scanners: [],
      fetch: async () => ({ exitCode: 1, output: 'ERR_PNPM_FETCH_404' }),
    })).rejects.toThrow(/quarantine fetch failed/)
  })
})

describe('advisory impact', () => {
  it('reads availability-only, data and integrity impacts from CVSS vectors, else CWEs', async () => {
    const { advisoryImpact, advisory } = await import('../src/host/engine/scanners.ts')
    expect(advisoryImpact(['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'], [])).toBe('availability')
    expect(advisoryImpact(['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H'], [])).toBe('integrity')
    expect(advisoryImpact(['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'], [])).toBe('confidentiality')
    expect(advisoryImpact(['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N'], [])).toBe('availability')
    expect(advisoryImpact([], ['CWE-1333', 'CWE-400'])).toBe('availability')
    expect(advisoryImpact([], ['CWE-1321'])).toBe('integrity')
    expect(advisoryImpact([], [])).toBe('unknown')
    expect(advisory('high', 'availability', DEFAULT_CONFIG)).toEqual({ category: 'denial-of-service', severity: 'low' })
    expect(advisory('low', 'integrity', DEFAULT_CONFIG)).toEqual({ category: 'integrity', severity: 'low' })
    expect(advisory('high', 'availability', applySettings(DEFAULT_CONFIG, { policy: { availabilitySeverity: 'high' } }))).toMatchObject({ severity: 'high' })
  })
})
