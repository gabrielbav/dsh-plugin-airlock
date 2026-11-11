/**
 * Quarantine layout, file copy and digest, and the inventory of skills, subagent prompts, MCP tool definitions and
 * configuration risks a package carries.
 */
import { createHash } from 'node:crypto'
import { copyFile, lstat, mkdir, readdir, readFile, writeFile } from 'node:fs/promises'
import { join, relative, sep } from 'node:path'
import { isMap, isScalar, isSeq, parseAllDocuments, type Node } from 'yaml'
import type { ScannedFinding } from '../types.ts'

/**
 * Directory names a local directory's walk skips: its own install output and history, which the profile's link does
 * not install. A fetched package keeps every directory it ships.
 */
export const LOCAL_SKIPPED_DIRS: ReadonlySet<string> = new Set(['node_modules', '.git'])

/**
 * Files a package walk visits, relative to its root with `/` separators, in sorted order.
 * @param root Package directory.
 * @param skipped Directory names not entered.
 * @returns Regular files and the symlinks that were not followed.
 */
export async function listFiles(root: string, skipped: ReadonlySet<string> = new Set()): Promise<{ files: string[]; symlinks: string[] }> {
  const files: string[] = []
  const symlinks: string[] = []
  const walk = async (dir: string): Promise<void> => {
    const entries = (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)
    for (const entry of entries) {
      const path = join(dir, entry.name)
      const rel = relative(root, path).split(sep).join('/')
      if (entry.isSymbolicLink()) symlinks.push(rel)
      else if (entry.isDirectory()) { if (!skipped.has(entry.name)) await walk(path) }
      else if (entry.isFile()) files.push(rel)
    }
  }
  await walk(root)
  return { files, symlinks }
}

/**
 * SHA-256 over every regular file's relative path and content hash; symlinks and skipped directories are excluded.
 * @param root Package directory.
 * @param skipped Directory names not entered.
 * @returns Hex digest.
 */
export async function digestTree(root: string, skipped: ReadonlySet<string> = new Set()): Promise<string> {
  const { files } = await listFiles(root, skipped)
  const hash = createHash('sha256')
  for (const file of files) {
    hash.update(file).update('\0')
    hash.update(createHash('sha256').update(await readFile(join(root, file))).digest('hex')).update('\n')
  }
  return hash.digest('hex')
}

/**
 * Copy a package's regular files into the subject directory the scanners read.
 * @param from Package directory as fetched.
 * @param to Empty subject directory.
 * @param skipped Directory names not copied.
 * @returns The symlinks that were not copied.
 */
export async function copySubject(from: string, to: string, skipped: ReadonlySet<string>): Promise<string[]> {
  const { files, symlinks } = await listFiles(from, skipped)
  for (const file of files) {
    const target = join(to, file)
    await mkdir(join(target, '..'), { recursive: true })
    await copyFile(join(from, file), target)
  }
  return symlinks
}

/** What a package carries besides its code. */
export interface Inventory {
  /** Directories, relative to the subject, holding a `SKILL.md`. */
  readonly skills: readonly string[]
  /** Synthetic skill directories under the prompts root, one per extracted prompt. */
  readonly prompts: readonly { readonly dir: string; readonly source: string }[]
  /** JSON files, relative to the subject, holding MCP `tools/list` definitions. */
  readonly mcpToolFiles: readonly string[]
  readonly mcpTools: number
  /** Findings read directly from configuration: `!!js` expressions and declared MCP server commands. */
  readonly configFindings: readonly ScannedFinding[]
}

function isToolList(value: unknown): number {
  if (typeof value !== 'object' || value === null || !('tools' in value) || !Array.isArray(value.tools)) return 0
  const tools: unknown[] = value.tools
  return tools.every(tool => typeof tool === 'object' && tool !== null && 'name' in tool && typeof tool.name === 'string'
    && 'description' in tool && typeof tool.description === 'string') && tools.length > 0 ? tools.length : 0
}

/** Collect long strings under `config` keys of a parsed patch document, with the row id that holds them. */
function collectPrompts(node: Node | null | undefined, row: string, inConfig: boolean, minChars: number, out: { row: string; text: string }[]): void {
  if (node === null || node === undefined) return
  if (isScalar(node)) {
    if (inConfig && typeof node.value === 'string' && node.value.trim().length >= minChars) out.push({ row, text: node.value })
    return
  }
  if (isSeq(node)) {
    for (const item of node.items) collectPrompts(item as Node, row, inConfig, minChars, out)
    return
  }
  if (!isMap(node)) return
  const id = node.get('id')
  const here = typeof id === 'string' ? id : row
  for (const pair of node.items) {
    const key = isScalar(pair.key) ? String(pair.key.value) : ''
    collectPrompts(pair.value as Node, here, inConfig || key === 'config', minChars, out)
  }
}

/** Collect MCP server declarations: maps under a `servers` key whose entries name a `command` or `url`. */
function collectServers(node: Node | null | undefined, out: { name: string; target: string }[]): void {
  if (node === null || node === undefined) return
  if (isSeq(node)) { for (const item of node.items) collectServers(item as Node, out); return }
  if (!isMap(node)) return
  for (const pair of node.items) {
    const key = isScalar(pair.key) ? String(pair.key.value) : ''
    const value = pair.value as Node
    if (key === 'servers' && isMap(value)) {
      for (const server of value.items) {
        const entry = server.value
        if (!isMap(entry)) continue
        const command = entry.get('command')
        const url = entry.get('url')
        const args = entry.get('args')
        const argv = isSeq(args) ? args.items.map(item => isScalar(item) ? String(item.value) : '').join(' ') : ''
        const target = typeof command === 'string' ? `${command} ${argv}`.trim() : typeof url === 'string' ? url : undefined
        if (target !== undefined) out.push({ name: isScalar(server.key) ? String(server.key.value) : '?', target })
      }
    }
    collectServers(value, out)
  }
}

/**
 * Inventory a subject directory and write one synthetic skill per extracted prompt under `promptsRoot`, so the skill
 * scanners read subagent personas and instructions the way they read skills.
 * @param subject The copied package.
 * @param promptsRoot Empty directory for synthetic skills.
 * @param options Prompt length and JSON size thresholds.
 * @returns The inventory.
 */
export async function inventory(subject: string, promptsRoot: string, options: { promptMinChars: number; maxJsonBytes: number }): Promise<Inventory> {
  const { files } = await listFiles(subject)
  const skills = files.filter(file => file === 'SKILL.md' || file.endsWith('/SKILL.md')).map(file => file === 'SKILL.md' ? '.' : file.slice(0, -'/SKILL.md'.length))
  const mcpToolFiles: string[] = []
  let mcpTools = 0
  const prompts: { dir: string; source: string }[] = []
  const configFindings: ScannedFinding[] = []
  for (const file of files) {
    const path = join(subject, file)
    if (file.endsWith('.json')) {
      if ((await lstat(path)).size > options.maxJsonBytes) continue
      let parsed: unknown
      try { parsed = JSON.parse(await readFile(path, 'utf8')) }
      catch (error) { void error; continue } // Not JSON despite the name; nothing to inventory.
      const count = isToolList(parsed)
      if (count > 0) { mcpToolFiles.push(file); mcpTools += count }
      continue
    }
    if (!/\.ya?ml$/.test(file)) continue
    const text = await readFile(path, 'utf8')
    const lines = text.split('\n')
    lines.forEach((line, index) => {
      if (/!!?js\b/.test(line)) {
        configFindings.push({
          source: 'airlock', severity: 'medium', category: 'code_execution', title: 'Configuration evaluates a JavaScript expression when it loads',
          ruleId: 'AIRLOCK_CONFIG_JS', file, line: index + 1, dependency: false, dedupeKey: `js:${file}:${index + 1}`,
        })
      }
    })
    const found: { row: string; text: string }[] = []
    const servers: { name: string; target: string }[] = []
    for (const document of parseAllDocuments(text, { logLevel: 'silent' })) {
      if (!('contents' in document)) continue
      collectPrompts(document.contents, '', false, options.promptMinChars, found)
      collectServers(document.contents, servers)
    }
    for (const server of servers) {
      configFindings.push({
        source: 'airlock', severity: 'medium', category: 'mcp_server', title: `Declares MCP server "${server.name}": ${server.target}`,
        ruleId: 'AIRLOCK_MCP_SERVER', file, dependency: false, dedupeKey: `mcp:${file}:${server.name}`,
      })
    }
    for (const prompt of found) {
      const dir = join(promptsRoot, `prompt-${prompts.length + 1}`)
      await mkdir(dir, { recursive: true })
      const source = `${file}${prompt.row === '' ? '' : `#${prompt.row}`}`
      await writeFile(join(dir, 'SKILL.md'), `---\nname: prompt-${prompts.length + 1}\ndescription: Prompt text extracted from ${JSON.stringify(source)}\nlicense: UNLICENSED\n---\n\n${prompt.text}\n`)
      prompts.push({ dir: relative(promptsRoot, dir), source })
    }
  }
  return { skills, prompts, mcpToolFiles, mcpTools, configFindings }
}
