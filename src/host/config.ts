/**
 * Configuration: defaults, the Standard Schema validator Cordis applies to the `cordis.yml` row, validation of the
 * settings the person saves, and their merge into the effective configuration.
 */
import type { InstallGateSeverity } from './dsh.ts'
import {
  BUILTIN_SCANNERS, type AirlockConfig, type AirlockSettings, type BuiltinScannerId, type CustomScanner, type ScannerConfig,
} from './types.ts'

const SEVERITIES: readonly InstallGateSeverity[] = ['critical', 'high', 'medium', 'low', 'info']

const DEFAULT_COMMANDS: Readonly<Record<BuiltinScannerId, string>> = {
  'cisco-skill-scanner': 'skill-scanner',
  'skillscan': 'skillscan',
  'cisco-mcp-scanner': 'mcp-scanner',
  'osv-scanner': 'osv-scanner',
  'trivy': 'trivy',
  'gitleaks': 'gitleaks',
}

/** Built-in scanner display names. */
export const SCANNER_NAMES: Readonly<Record<BuiltinScannerId, string>> = {
  'cisco-skill-scanner': 'Cisco Skill Scanner',
  'skillscan': 'SkillScan',
  'cisco-mcp-scanner': 'Cisco MCP Scanner',
  'osv-scanner': 'OSV-Scanner',
  'trivy': 'Trivy',
  'gitleaks': 'Gitleaks',
}

/** The configuration with no `cordis.yml` config and no saved settings. */
export const DEFAULT_CONFIG: AirlockConfig = {
  scanners: Object.fromEntries(BUILTIN_SCANNERS.map(id => [id, { enabled: true, command: DEFAULT_COMMANDS[id] }])) as Record<BuiltinScannerId, ScannerConfig>,
  custom: [],
  searchPaths: ['~/.local/bin', '/opt/homebrew/bin', '/usr/local/bin'],
  scannerTimeoutMs: 600000,
  maxFindings: 200,
  promptMinChars: 80,
  maxJsonBytes: 1024 * 1024,
  policy: {
    passScore: 85, blockScore: 40, blockSeverity: 'critical', dependencyBlockSeverity: 'critical', reviewSeverity: 'medium', availabilitySeverity: 'low',
    weights: { critical: 50, high: 25, medium: 10, low: 3, info: 0 }, dependencyWeight: 0.5, requireLlm: true,
  },
  llm: { enabled: false, provider: '', model: '' },
  installCommands: {
    'cisco-skill-scanner': ['uv', 'tool', 'install', 'cisco-ai-skill-scanner'],
    'skillscan': ['uv', 'tool', 'install', '--python', '3.12', 'skillscan'],
    'cisco-mcp-scanner': ['uv', 'tool', 'install', '--python', '3.13', 'cisco-ai-mcp-scanner'],
    'osv-scanner': ['brew', 'install', 'osv-scanner'],
    'trivy': ['brew', 'install', 'trivy'],
    'gitleaks': ['brew', 'install', 'gitleaks'],
  },
  installTimeoutMs: 900000,
}

/** A validation failure naming the path it found. */
export class ConfigError extends Error {
  /** @param path Dotted path of the invalid value. @param message What was expected. */
  constructor(readonly path: string, message: string) { super(`${path}: ${message}`) }
}

type Json = Record<string, unknown>

function object(value: unknown, path: string): Json {
  if (value === undefined) return {}
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new ConfigError(path, 'expected an object')
  return value as Json
}

function bool(value: unknown, fallback: boolean, path: string): boolean {
  if (value === undefined) return fallback
  if (typeof value !== 'boolean') throw new ConfigError(path, 'expected true or false')
  return value
}

function str(value: unknown, fallback: string, path: string, nonEmpty = false): string {
  if (value === undefined) return fallback
  if (typeof value !== 'string' || (nonEmpty && value.trim() === '')) throw new ConfigError(path, nonEmpty ? 'expected a non-empty string' : 'expected a string')
  return value
}

function num(value: unknown, fallback: number, path: string, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (value === undefined) return fallback
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) throw new ConfigError(path, `expected a number from ${min} to ${max}`)
  return value
}

function severity(value: unknown, fallback: InstallGateSeverity, path: string): InstallGateSeverity {
  if (value === undefined) return fallback
  if (!SEVERITIES.includes(value as InstallGateSeverity)) throw new ConfigError(path, `expected one of ${SEVERITIES.join(', ')}`)
  return value as InstallGateSeverity
}

function strings(value: unknown, fallback: readonly string[], path: string): readonly string[] {
  if (value === undefined) return fallback
  if (!Array.isArray(value) || value.some(item => typeof item !== 'string')) throw new ConfigError(path, 'expected a list of strings')
  return value as string[]
}

/** Custom scanner ids: lower-case words that cannot shadow a built-in. */
const CUSTOM_ID = /^[a-z0-9][a-z0-9-]{0,39}$/

function custom(value: unknown, path: string): CustomScanner[] {
  if (value === undefined) return []
  if (!Array.isArray(value)) throw new ConfigError(path, 'expected a list')
  const seen = new Set<string>()
  return value.map((item, index) => {
    const at = `${path}.${index}`
    const raw = object(item, at)
    const id = str(raw.id, '', `${at}.id`, true)
    if (!CUSTOM_ID.test(id) || (BUILTIN_SCANNERS as readonly string[]).includes(id) || id === 'airlock') throw new ConfigError(`${at}.id`, 'expected a lower-case id that is not a built-in scanner')
    if (seen.has(id)) throw new ConfigError(`${at}.id`, `duplicate id ${id}`)
    seen.add(id)
    const target = str(raw.target, 'package', `${at}.target`)
    if (target !== 'package' && target !== 'lockfile') throw new ConfigError(`${at}.target`, 'expected package or lockfile')
    const codes = raw.okExitCodes === undefined ? [0, 1] : raw.okExitCodes
    if (!Array.isArray(codes) || codes.some(code => !Number.isInteger(code))) throw new ConfigError(`${at}.okExitCodes`, 'expected a list of integers')
    return {
      id, name: str(raw.name, id, `${at}.name`, true), enabled: bool(raw.enabled, true, `${at}.enabled`),
      command: str(raw.command, '', `${at}.command`, true), args: strings(raw.args, ['{target}'], `${at}.args`), target, okExitCodes: codes as number[],
    }
  })
}

/**
 * Validate saved settings: every field optional, unknown fields refused so a typo never silently does nothing.
 * @param value Decoded JSON.
 * @returns The settings.
 * @throws {ConfigError} For any invalid field.
 */
export function parseSettings(value: unknown): AirlockSettings {
  const raw = object(value, 'settings')
  for (const key of Object.keys(raw)) if (!['scanners', 'custom', 'policy', 'llm'].includes(key)) throw new ConfigError(key, 'unknown setting')
  const scanners = object(raw.scanners, 'scanners')
  const policy = object(raw.policy, 'policy')
  const llm = object(raw.llm, 'llm')
  const parsedScanners: Partial<Record<BuiltinScannerId, Partial<ScannerConfig>>> = {}
  for (const [id, entry] of Object.entries(scanners)) {
    if (!(BUILTIN_SCANNERS as readonly string[]).includes(id)) throw new ConfigError(`scanners.${id}`, 'unknown scanner')
    const item = object(entry, `scanners.${id}`)
    parsedScanners[id as BuiltinScannerId] = {
      ...item.enabled === undefined ? {} : { enabled: bool(item.enabled, true, `scanners.${id}.enabled`) },
      ...item.command === undefined ? {} : { command: str(item.command, '', `scanners.${id}.command`, true) },
    }
  }
  const pick = <T>(source: Json, key: string, read: (value: unknown) => T): Record<string, T> => source[key] === undefined ? {} : { [key]: read(source[key]) }
  return {
    scanners: parsedScanners,
    ...raw.custom === undefined ? {} : { custom: custom(raw.custom, 'custom') },
    policy: {
      ...pick(policy, 'passScore', value => num(value, 0, 'policy.passScore', 0, 100)),
      ...pick(policy, 'blockScore', value => num(value, 0, 'policy.blockScore', 0, 100)),
      ...pick(policy, 'blockSeverity', value => severity(value, 'critical', 'policy.blockSeverity')),
      ...pick(policy, 'dependencyBlockSeverity', value => severity(value, 'critical', 'policy.dependencyBlockSeverity')),
      ...pick(policy, 'reviewSeverity', value => severity(value, 'medium', 'policy.reviewSeverity')),
      ...pick(policy, 'availabilitySeverity', value => severity(value, 'low', 'policy.availabilitySeverity')),
      ...pick(policy, 'dependencyWeight', value => num(value, 0, 'policy.dependencyWeight', 0, 10)),
      ...pick(policy, 'requireLlm', value => bool(value, true, 'policy.requireLlm')),
    },
    llm: {
      ...pick(llm, 'enabled', value => bool(value, false, 'llm.enabled')),
      ...pick(llm, 'provider', value => str(value, '', 'llm.provider')),
      ...pick(llm, 'model', value => str(value, '', 'llm.model')),
    },
  }
}

/**
 * Validate the `cordis.yml` config of the Airlock row, filling defaults.
 * @param value The row's config.
 * @returns The configuration.
 * @throws {ConfigError} For any invalid field.
 */
export function parseConfig(value: unknown): AirlockConfig {
  const raw = object(value, 'config')
  const settings = parseSettings(Object.fromEntries(Object.entries(raw).filter(([key]) => ['scanners', 'custom', 'policy', 'llm'].includes(key))))
  const base = applySettings(DEFAULT_CONFIG, settings)
  const weights = object(object(raw.policy, 'policy').weights, 'policy.weights')
  const installs = object(raw.installCommands, 'installCommands')
  return {
    ...base,
    searchPaths: strings(raw.searchPaths, DEFAULT_CONFIG.searchPaths, 'searchPaths'),
    scannerTimeoutMs: num(raw.scannerTimeoutMs, DEFAULT_CONFIG.scannerTimeoutMs, 'scannerTimeoutMs', 1000),
    maxFindings: num(raw.maxFindings, DEFAULT_CONFIG.maxFindings, 'maxFindings', 1),
    promptMinChars: num(raw.promptMinChars, DEFAULT_CONFIG.promptMinChars, 'promptMinChars', 1),
    maxJsonBytes: num(raw.maxJsonBytes, DEFAULT_CONFIG.maxJsonBytes, 'maxJsonBytes', 1),
    installTimeoutMs: num(raw.installTimeoutMs, DEFAULT_CONFIG.installTimeoutMs, 'installTimeoutMs', 1000),
    policy: {
      ...base.policy,
      weights: Object.fromEntries(SEVERITIES.map(level => [level, num(weights[level], DEFAULT_CONFIG.policy.weights[level], `policy.weights.${level}`, 0)])) as AirlockConfig['policy']['weights'],
    },
    installCommands: Object.fromEntries(BUILTIN_SCANNERS.map(id => [id, strings(installs[id], DEFAULT_CONFIG.installCommands[id], `installCommands.${id}`)])) as AirlockConfig['installCommands'],
  }
}

/**
 * Apply saved settings over a configuration.
 * @param config Base configuration.
 * @param settings The person's settings.
 * @returns The effective configuration.
 * @throws {ConfigError} When the block score would exceed the pass score.
 */
export function applySettings(config: AirlockConfig, settings: AirlockSettings): AirlockConfig {
  const policy = { ...config.policy, ...settings.policy }
  if (policy.blockScore > policy.passScore) throw new ConfigError('policy.blockScore', 'must not exceed policy.passScore')
  return {
    ...config,
    scanners: Object.fromEntries(BUILTIN_SCANNERS.map(id => [id, { ...config.scanners[id], ...settings.scanners?.[id] }])) as AirlockConfig['scanners'],
    custom: settings.custom ?? config.custom,
    policy,
    llm: { ...config.llm, ...settings.llm },
  }
}

/** Standard Schema validator Cordis applies to the plugin's row config. */
export const Config = {
  '~standard': {
    version: 1,
    vendor: 'dsh-plugin-airlock',
    validate(value: unknown) {
      try { return { value: parseConfig(value ?? {}) } }
      catch (error) {
        if (!(error instanceof ConfigError)) throw error
        return { issues: [{ message: error.message, path: error.path.split('.') }] }
      }
    },
  },
} as const
