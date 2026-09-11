// src/api/adapters.ts
import type { Rule, RuleProvider } from '@/types'

/**
 * 1. 将 sing-box 的 /rules 数据转换为项目 1 的统一 Rule 模型
 */
export function normalizeSingboxRules(rawRules: Record<string, unknown>[]): Rule[] {
  if (!Array.isArray(rawRules)) return []

  return rawRules.map((item, index) => {
    const ruleType = String(item.type || item.rule_type || 'Unknown')
    const rawProxy = String(item.outbound || item.proxy || 'Direct')
    const proxy = rawProxy.startsWith('route(') ? rawProxy.slice(6, -1) : rawProxy

    let payload = ''
    if (typeof item.payload === 'string') {
      payload = item.payload
    } else if (Array.isArray(item.payload)) {
      payload = item.payload.join(', ')
    } else if (Array.isArray(item.domain)) {
      payload = item.domain.join(', ')
    } else if (item.query) {
      payload = String(item.query)
    }

    return {
      index,
      type: ruleType,
      payload,
      proxy,
      size: item.size ?? (Array.isArray(item.payload) ? item.payload.length : 0),
      disabled: Boolean(item.disabled),
      extra: item.extra || undefined,
    } as Rule
  })
}

/**
 * 2. 补全漏掉的导出：将 sing-box 的 /providers/rules 转换为统一的 RuleProvider 模型
 */
export function normalizeSingboxProviders(
  rawProviders: Record<string, Record<string, unknown>>,
): Record<string, RuleProvider> {
  const normalized: Record<string, RuleProvider> = {}

  Object.entries(rawProviders || {}).forEach(([key, provider]) => {
    normalized[key] = {
      name: provider.name || key,
      type: provider.type || 'http',
      behavior: provider.behavior || provider.rule_set_type || 'classical',
      vehicleType: provider.vehicleType || 'HTTP',
      updatedAt: provider.updatedAt || provider.last_updated || '',
      ruleCount: provider.ruleCount ?? provider.item_count ?? 0,
      format: provider.format || (provider.type === 'inline' ? 'inline' : 'binary'),
    } as RuleProvider
  })

  return normalized
}
