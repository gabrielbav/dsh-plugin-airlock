/** Stored report format: reports written by Airlock 0.1.0 before the generic install-gate report are read in the current format. */
import type { InstallGateReport } from './dsh.ts'
import { REASON_TEXT, type AirlockReason } from './reasons.ts'
import { GATE_ID } from './engine/index.ts'

type Legacy = Record<string, unknown>

/**
 * Read a stored report, converting the 0.1.0 format (`scanners`, `inventory`, `scannedAt`, reason codes, `scanner` on
 * findings) to the install-gate report.
 * @param value Decoded JSON of one report file.
 * @returns The report in the current format.
 */
export function upgradeReport(value: unknown): InstallGateReport {
  const report = value as Legacy
  if (!('scannedAt' in report)) return value as InstallGateReport
  const { scanners, inventory, scannedAt, reasons, findings, ...rest } = report
  const upgraded: Legacy = {
    ...rest,
    reasons: (Array.isArray(reasons) ? reasons : []).map(reason => typeof reason === 'string'
      ? REASON_TEXT[reason as AirlockReason] ?? { en: reason } : reason),
    ...Array.isArray(scanners) ? { checks: scanners } : {},
    ...typeof inventory === 'object' && inventory !== null ? { metrics: inventory } : {},
    findings: (Array.isArray(findings) ? findings as Legacy[] : []).map(({ scanner, ...finding }) => ({ source: String(scanner ?? 'airlock'), ...finding })),
    gates: [GATE_ID],
    checkedAt: String(scannedAt),
  }
  // Stored files are this plugin's own output; their fields were written by the 0.1.0 report builder.
  return upgraded as unknown as InstallGateReport
}
