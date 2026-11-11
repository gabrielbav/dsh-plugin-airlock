/**
 * A local OpenAI-compatible endpoint that forwards the scanners' LLM requests to the DSH model the person selected, so
 * any model the chat offers, including subscription logins, can judge a package without an API key in Airlock's
 * settings. It listens on 127.0.0.1 only, requires a per-scan bearer token, and lives for one scan.
 */
import { randomBytes } from 'node:crypto'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import type { LlmService } from './dsh.ts'

/** The model name scanners send; the bridge maps it to the selected DSH route. */
export const BRIDGE_MODEL = 'airlock-judge'

/** A running bridge. */
export interface LlmBridge {
  /** OpenAI-compatible base URL, ending in `/v1`. */
  readonly baseUrl: string
  /** Bearer token the scanners send. */
  readonly apiKey: string
  /**
   * Requests answered with a model reply, for one model name or in total. Scanners use distinct model names, so each
   * can tell whether its judge actually answered; some scanners report a verdict even when their call failed.
   */
  readonly calls: (model?: string) => number
  close(): Promise<void>
}

/** Largest request body accepted, in bytes. */
const MAX_BODY = 8 * 1024 * 1024

interface ChatMessage { role?: unknown; content?: unknown }

/** OpenAI message content as plain text: a string, or the text parts of a content array. */
function textOf(content: unknown): string {
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  return content.map(part => typeof part === 'object' && part !== null && 'text' in part && typeof part.text === 'string' ? part.text : '').join('')
}

async function readBody(request: IncomingMessage): Promise<string> {
  let size = 0
  const chunks: Buffer[] = []
  for await (const chunk of request) {
    const buffer = chunk as Buffer
    size += buffer.length
    if (size > MAX_BODY) throw new Error('request body too large')
    chunks.push(buffer)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function send(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json' })
  response.end(JSON.stringify(body))
}

/**
 * Start a bridge to one DSH model route.
 * @param llm The model-call service.
 * @param route The selected provider and model.
 * @param signal Ends in-flight model calls when the scan is cancelled.
 * @returns The bridge.
 */
export async function startLlmBridge(
  llm: LlmService, route: { provider: string; model: string }, signal: AbortSignal, onError: (message: string) => void = () => {},
): Promise<LlmBridge> {
  const apiKey = randomBytes(24).toString('base64url')
  const answered = new Map<string, number>()
  const server = createServer((request, response) => {
    void (async () => {
      if (request.headers.authorization !== `Bearer ${apiKey}`) return send(response, 401, { error: { message: 'unauthorized' } })
      const path = (request.url ?? '').split('?')[0]
      if (request.method === 'GET' && path === '/v1/models') {
        return send(response, 200, { object: 'list', data: [{ id: BRIDGE_MODEL, object: 'model', owned_by: 'airlock' }] })
      }
      if (request.method !== 'POST' || path !== '/v1/chat/completions') return send(response, 404, { error: { message: 'not found' } })
      let body: { model?: unknown; messages?: unknown; stream?: unknown; max_tokens?: unknown; max_completion_tokens?: unknown; temperature?: unknown; response_format?: unknown }
      try { body = JSON.parse(await readBody(request)) as typeof body }
      catch (error) { return send(response, 400, { error: { message: error instanceof Error ? error.message : 'invalid body' } }) }
      const messages = Array.isArray(body.messages) ? body.messages as ChatMessage[] : []
      const format = formatInstruction(body.response_format)
      const system = [...messages.filter(message => message.role === 'system' || message.role === 'developer').map(message => textOf(message.content)), format]
        .filter(part => part !== '').join('\n\n')
      // Prior turns fold into one user input: DSH's one-shot requests carry user content only.
      const conversation = messages.filter(message => message.role !== 'system' && message.role !== 'developer')
        .map(message => conversationText(message)).join('\n\n')
      const maxTokens = typeof body.max_completion_tokens === 'number' ? body.max_completion_tokens : typeof body.max_tokens === 'number' ? body.max_tokens : undefined
      let text = ''
      let finish = 'stop'
      let failure = ''
      try {
        for await (const chunk of llm.stream({
          provider: route.provider, model: route.model, ...system === '' ? {} : { system },
          messages: [{ role: 'user', content: [{ type: 'text', text: conversation === '' ? '(empty)' : conversation }] }],
          ...maxTokens === undefined ? {} : { maxTokens }, ...typeof body.temperature === 'number' ? { temperature: body.temperature } : {},
          signal,
        })) {
          if (chunk.type === 'text-delta' && 'text' in chunk) text += chunk.text
          if (chunk.type === 'finish' && 'reason' in chunk) {
            finish = chunk.reason.kind
            failure = chunk.reason.failure?.message ?? ''
          }
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        onError(`model call failed: ${message}`)
        return send(response, 502, { error: { message } })
      }
      if (finish !== 'stop' && finish !== 'max-tokens') {
        const message = `model call ended with ${finish}${failure === '' ? '' : `: ${failure}`}`
        onError(message)
        return send(response, 502, { error: { message } })
      }
      if (format !== '') text = jsonOnly(text)
      const name = typeof body.model === 'string' ? body.model : BRIDGE_MODEL
      answered.set(name, (answered.get(name) ?? 0) + 1)
      const id = `airlock-${randomBytes(6).toString('hex')}`
      if (body.stream === true) {
        response.writeHead(200, { 'content-type': 'text/event-stream' })
        response.write(`data: ${JSON.stringify({ id, object: 'chat.completion.chunk', model: BRIDGE_MODEL, choices: [{ index: 0, delta: { role: 'assistant', content: text }, finish_reason: null }] })}\n\n`)
        response.write(`data: ${JSON.stringify({ id, object: 'chat.completion.chunk', model: BRIDGE_MODEL, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] })}\n\n`)
        response.end('data: [DONE]\n\n')
        return undefined
      }
      return send(response, 200, {
        id, object: 'chat.completion', created: Math.floor(Date.now() / 1000), model: BRIDGE_MODEL,
        choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: finish === 'max-tokens' ? 'length' : 'stop' }],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      })
    })().catch(() => { if (!response.headersSent) send(response, 500, { error: { message: 'bridge failure' } }) })
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => { resolve() })
  })
  const { port } = server.address() as AddressInfo
  return {
    baseUrl: `http://127.0.0.1:${port}/v1`, apiKey,
    calls: model => model === undefined ? [...answered.values()].reduce((sum, count) => sum + count, 0) : answered.get(model) ?? 0,
    close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => { resolve() }) }),
  }
}

function conversationText(message: ChatMessage): string {
  const content = textOf(message.content)
  return message.role === 'assistant' ? `[assistant]\n${content}` : content
}

/**
 * The instruction that stands in for OpenAI structured output, which DSH model routes do not take: the schema the
 * caller requires, stated in the system prompt.
 * @param format The request's `response_format`.
 * @returns The instruction, or an empty string when the caller wants free text.
 */
export function formatInstruction(format: unknown): string {
  if (typeof format !== 'object' || format === null || !('type' in format)) return ''
  const only = 'Answer with exactly one JSON object and nothing else: no prose, no explanation, no Markdown code fences.'
  if (format.type === 'json_object') return only
  if (format.type !== 'json_schema' || !('json_schema' in format)) return ''
  const spec = format.json_schema
  const schema = typeof spec === 'object' && spec !== null && 'schema' in spec ? spec.schema : spec
  return `${only} The object must validate against this JSON Schema; use only the property names and enum values it allows, and include every required property:\n${JSON.stringify(schema)}`
}

/**
 * Reduce a model answer to its JSON object: drop code fences and any text around the outermost braces.
 * @param text The model's answer.
 * @returns The JSON text, or the answer unchanged when it holds no object.
 */
export function jsonOnly(text: string): string {
  const unfenced = text.replace(/```(?:json)?/gi, '')
  const start = unfenced.indexOf('{')
  const end = unfenced.lastIndexOf('}')
  return start === -1 || end <= start ? text : unfenced.slice(start, end + 1)
}
