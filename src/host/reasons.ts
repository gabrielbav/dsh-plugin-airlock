/** Airlock's reasons for a non-pass ruling, localized for the install gate report. */
import type { InstallGateText } from './dsh.ts'

/** Why Airlock does not pass a package. */
export type AirlockReason =
  | 'finding-blocks'
  | 'score-below-block'
  | 'score-below-pass'
  | 'findings-need-review'
  | 'scanner-unavailable'
  | 'scanner-error'
  | 'llm-not-run'

/** The localized text of each reason, in every DSH locale. */
export const REASON_TEXT: Readonly<Record<AirlockReason, InstallGateText>> = {
  'finding-blocks': {
    en: "A finding is severe enough to block installation.",
    zh: "有发现严重到足以阻止安装。",
    ja: "インストールをブロックするほど深刻な検出結果があります。",
    es: "Un hallazgo es lo bastante grave para bloquear la instalación.",
    fr: "Un résultat est assez grave pour bloquer l'installation.",
    de: "Ein Befund ist schwer genug, um die Installation zu blockieren.",
    ru: "Есть находка, достаточно серьёзная, чтобы заблокировать установку.",
    pt: "Um resultado é grave o bastante para bloquear a instalação.",
  },
  'score-below-block': {
    en: "The score is below the block threshold.",
    zh: "评分低于阻止阈值。",
    ja: "スコアがブロックのしきい値を下回っています。",
    es: "La puntuación está por debajo del umbral de bloqueo.",
    fr: "Le score est sous le seuil de blocage.",
    de: "Die Bewertung liegt unter der Sperrschwelle.",
    ru: "Оценка ниже порога блокировки.",
    pt: "A pontuação está abaixo do limite de bloqueio.",
  },
  'score-below-pass': {
    en: "The score is below the pass threshold.",
    zh: "评分低于通过阈值。",
    ja: "スコアが合格のしきい値を下回っています。",
    es: "La puntuación está por debajo del umbral de aprobación.",
    fr: "Le score est sous le seuil de validation.",
    de: "Die Bewertung liegt unter der Bestehensschwelle.",
    ru: "Оценка ниже порога прохождения.",
    pt: "A pontuação está abaixo do limite de aprovação.",
  },
  'findings-need-review': {
    en: "Some findings need review.",
    zh: "部分发现需要审查。",
    ja: "確認が必要な検出結果があります。",
    es: "Algunos hallazgos requieren revisión.",
    fr: "Certains résultats sont à examiner.",
    de: "Einige Befunde müssen geprüft werden.",
    ru: "Некоторые находки требуют проверки.",
    pt: "Alguns resultados precisam de revisão.",
  },
  'scanner-unavailable': {
    en: "A scanner isn't installed, so the scan is incomplete.",
    zh: "有扫描器未安装，扫描不完整。",
    ja: "インストールされていないスキャナーがあるため、スキャンは不完全です。",
    es: "Falta instalar un escáner, así que el análisis está incompleto.",
    fr: "Un scanner n'est pas installé ; l'analyse est incomplète.",
    de: "Ein Scanner ist nicht installiert, daher ist der Scan unvollständig.",
    ru: "Один из сканеров не установлен, поэтому проверка неполная.",
    pt: "Um scanner não está instalado, então a análise está incompleta.",
  },
  'scanner-error': {
    en: "A scanner failed, so the scan is incomplete.",
    zh: "有扫描器运行失败，扫描不完整。",
    ja: "失敗したスキャナーがあるため、スキャンは不完全です。",
    es: "Un escáner falló, así que el análisis está incompleto.",
    fr: "Un scanner a échoué ; l'analyse est incomplète.",
    de: "Ein Scanner ist fehlgeschlagen, daher ist der Scan unvollständig.",
    ru: "Один из сканеров завершился с ошибкой, поэтому проверка неполная.",
    pt: "Um scanner falhou, então a análise está incompleta.",
  },
  'llm-not-run': {
    en: "The LLM analysis is turned off, so the best possible result is a review.",
    zh: "LLM 分析已关闭，因此最好的结果是需要审查。",
    ja: "LLM 分析がオフのため、最良の結果でも確認が必要になります。",
    es: "El análisis con LLM está desactivado, así que el mejor resultado posible es una revisión.",
    fr: "L'analyse par LLM est désactivée ; le meilleur résultat possible est un examen.",
    de: "Die LLM-Analyse ist ausgeschaltet, daher ist das bestmögliche Ergebnis eine Prüfung.",
    ru: "Анализ с помощью LLM выключен, поэтому лучший возможный результат — проверка.",
    pt: "A análise por LLM está desligada, então o melhor resultado possível é uma revisão.",
  },
}
