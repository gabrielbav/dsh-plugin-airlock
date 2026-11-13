/**
 * The ledger of bundles Airlock let in, and the audit that finds third-party bundles installed some other way: the
 * Plugins page's own install button on a DSH without the install-gate hook, Discover, the update dialog, or
 * `dsh plugin add` on the command line. The audit compares each installed bundle's files with the digest Airlock
 * scanned. It notices after the fact; only the hook or Airlock's own install stops a package before it installs.
 */
import { readFile } from 'node:fs/promises'
import { writePrivateFile } from './files.ts'
import type { BundleInfo } from './dsh.ts'

/** How a bundle came to be trusted. */
export type TrustSource = 'scan' | 'baseline' | 'user'

/** One trusted bundle. */
export interface LedgerEntry {
  /** Digest of the trusted files; null for a `link:` bundle, which is trusted by name. */
  readonly digest: string | null
  readonly how: TrustSource
  readonly version?: string
  readonly at: string
}

/** Everything the audit remembers, saved in `<profile>/.airlock/ledger.json`. */
export interface Ledger {
  readonly version: 1
  /** Trusted bundles by package name. */
  readonly approved: Readonly<Record<string, LedgerEntry>>
  /** The digest each bundle had when Airlock switched it off, so a bundle the person switches back on stays on. */
  readonly disabled: Readonly<Record<string, string>>
}

/** What the audit says about one installed bundle. */
export type BundleStatus =
  /** Its files are the ones Airlock scanned. */
  | 'vetted'
  /** It was installed before Airlock first ran. */
  | 'baseline'
  /** The person chose to trust it without a passing scan. */
  | 'trusted'
  /** Airlock has never seen it. */
  | 'unscanned'
  /** Its files changed since Airlock trusted them, for example after an update. */
  | 'changed'

/** An empty ledger. */
export const EMPTY_LEDGER: Ledger = { version: 1, approved: {}, disabled: {} }

/**
 * Read the ledger.
 * @param path Ledger file.
 * @returns The ledger, or null when Airlock has never run in this profile.
 */
export async function readLedger(path: string): Promise<Ledger | null> {
  let text: string
  try { text = await readFile(path, 'utf8') }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
  const raw = JSON.parse(text) as Partial<Ledger>
  return { version: 1, approved: raw.approved ?? {}, disabled: raw.disabled ?? {} }
}

/**
 * Save the ledger as an owner-only file.
 * @param path Ledger file.
 * @param ledger The ledger.
 */
export async function writeLedger(path: string, ledger: Ledger): Promise<void> {
  await writePrivateFile(path, `${JSON.stringify(ledger, null, 2)}\n`)
}

/**
 * Whether a bundle is one the audit looks at: a third-party package installed in this profile, other than Airlock.
 * Official bundles and the packages the DSH installation ships are left alone.
 * @param bundle One listed bundle.
 * @param self Airlock's package name.
 * @returns True for an audited bundle.
 */
export function audited(bundle: BundleInfo, self: string): boolean {
  return bundle.installed && bundle.availability === 'profile' && !bundle.official && bundle.name !== self
}

/** Whether a bundle is linked to a local directory, whose files change whenever its author rebuilds it. */
export function linked(bundle: BundleInfo): boolean {
  return bundle.source?.startsWith('link:') === true
}

/**
 * The audit status of one bundle.
 * @param entry Its ledger entry, if any.
 * @param digest Digest of its installed files; null for a linked bundle.
 * @returns The status.
 */
export function statusOf(entry: LedgerEntry | undefined, digest: string | null): BundleStatus {
  if (entry === undefined) return 'unscanned'
  const same = digest === null || entry.digest === null || entry.digest === digest
  if (!same) return 'changed'
  return entry.how === 'scan' ? 'vetted' : entry.how === 'baseline' ? 'baseline' : 'trusted'
}

/** One audited bundle and what the audit decided. */
export interface AuditedBundle {
  readonly name: string
  readonly status: BundleStatus
  readonly digest: string | null
  /** Airlock switched it off in this audit. */
  readonly disable: boolean
}

/**
 * Audit every installed bundle against the ledger.
 * @param options.bundles The plugin manager's bundle list.
 * @param options.ledger The ledger; null on Airlock's first run in this profile, which trusts what is already there.
 * @param options.digestOf Digest of a bundle's installed files; null for a linked bundle or one with no files.
 * @param options.disable Whether to switch off bundles that are not trusted.
 * @param options.self Airlock's package name.
 * @returns The updated ledger and each audited bundle.
 */
export async function audit(options: {
  readonly bundles: readonly BundleInfo[]
  readonly ledger: Ledger | null
  readonly digestOf: (bundle: BundleInfo) => Promise<string | null>
  readonly disable: boolean
  readonly self: string
  readonly now?: () => string
}): Promise<{ ledger: Ledger; bundles: AuditedBundle[] }> {
  const now = options.now ?? (() => new Date().toISOString())
  const approved: Record<string, LedgerEntry> = { ...options.ledger?.approved }
  const disabled: Record<string, string> = { ...options.ledger?.disabled }
  const results: AuditedBundle[] = []
  const present = new Set<string>()
  for (const bundle of options.bundles.filter(item => audited(item, options.self))) {
    present.add(bundle.name)
    const digest = linked(bundle) ? null : await options.digestOf(bundle)
    if (options.ledger === null) {
      approved[bundle.name] = { digest, how: 'baseline', ...bundle.version === undefined ? {} : { version: bundle.version }, at: now() }
    }
    const status = statusOf(approved[bundle.name], digest)
    const untrusted = status === 'unscanned' || status === 'changed'
    // Switched off once per set of files: a person who turns it back on has decided, and Airlock leaves it on.
    const disable = untrusted && options.disable && bundle.enabled && disabled[bundle.name] !== (digest ?? '')
    if (disable) disabled[bundle.name] = digest ?? ''
    results.push({ name: bundle.name, status, digest, disable })
  }
  // A removed bundle starts over if it is installed again.
  for (const name of Object.keys(disabled)) if (!present.has(name)) delete disabled[name]
  return { ledger: { version: 1, approved, disabled }, bundles: results }
}
