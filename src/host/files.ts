/** Atomic owner-only file writes for settings and reports. */
import { randomUUID } from 'node:crypto'
import { rename, rm, writeFile } from 'node:fs/promises'

/**
 * Write a file atomically with mode 0600: a temporary sibling is written, then renamed over the target.
 * @param path Target file.
 * @param text Content.
 */
export async function writePrivateFile(path: string, text: string): Promise<void> {
  const temporary = `${path}.${randomUUID()}.tmp`
  try {
    await writeFile(temporary, text, { mode: 0o600 })
    await rename(temporary, path)
  } catch (error) {
    await rm(temporary, { force: true })
    throw error
  }
}
