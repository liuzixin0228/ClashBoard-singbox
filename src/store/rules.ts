import { fetchRuleProvidersAPI, fetchRulesAPI } from '@/api'
import { RULE_TAB_TYPE } from '@/constant'
import { isProxyRuleEnabled, isRuleSetProxyRule } from '@/helper/proxyDomainGroups'
import { fetchServerApi } from '@/store/auth'
import type { Rule, RuleProvider } from '@/types'
import { useStorage } from '@vueuse/core'
import { computed, ref } from 'vue'
// 增加导入 normalizeSingboxRules 和 normalizeSingboxProviders
import { normalizeSingboxProviders, normalizeSingboxRules } from '@/api/adapters'

export type RuleRefreshPhase = 'idle' | 'provider' | 'cache'

export const isSingboxKernel = ref(false)

export type RuleRefreshState = {
  runId: number
  isRefreshing: boolean
  scope: 'all' | 'provider'
  providerName: string
  phase: RuleRefreshPhase
  totalProviders: number
  updatedProviders: number
  totalRules: number
  errors: number
  cancelled: boolean
  completed: boolean
  lastError: string
  completedAt: number
  updatedAt: number
}

const createDefaultRuleRefreshState = (): RuleRefreshState => ({
  runId: 0,
  isRefreshing: false,
  scope: 'all',
  providerName: '',
  phase: 'idle',
  totalProviders: 0,
  updatedProviders: 0,
  totalRules: 0,
  errors: 0,
  cancelled: false,
  completed: false,
  lastError: '',
  completedAt: 0,
  updatedAt: 0,
})

export const rulesFilter = ref('')
export const rulesTabShow = useStorage<RULE_TAB_TYPE>('cache/rules-tab-show', RULE_TAB_TYPE.RULES)

export const rules = ref<Rule[]>([])
export const ruleProviderList = ref<RuleProvider[]>([])
export const ruleCacheTotalRules = ref(0)
export const ruleProviderLocalCountMap = ref<Record<string, number>>({})
export const ruleProviderSourceUrlMap = ref<Record<string, string>>({})
export const ruleProviderOrderList = ref<string[]>([])
export const ruleCacheRefreshCount = ref(0)
export const isRuleCacheUpdating = ref(false)
export const ruleRefreshState = ref<RuleRefreshState>(createDefaultRuleRefreshState())

export const renderRules = computed(() => {
  const rulesFilterValue = rulesFilter.value.split(' ').map((f) => f.toLowerCase().trim())

  if (rulesFilter.value === '') {
    return rules.value
  }

  return rules.value.filter((rule) => {
    return rulesFilterValue.every((f) =>
      [rule.type.toLowerCase(), rule.payload.toLowerCase(), rule.proxy.toLowerCase()].some((i) =>
        i.includes(f),
      ),
    )
  })
})

export const renderRulesProvider = computed(() => {
  const rulesFilterValue = rulesFilter.value.split(' ').map((f) => f.toLowerCase().trim())

  if (rulesFilter.value === '') {
    return visibleRuleProviderList.value
  }

  return visibleRuleProviderList.value.filter((ruleProvider) => {
    return rulesFilterValue.every((f) =>
      [
        ruleProvider.name.toLowerCase(),
        ruleProvider.behavior.toLowerCase(),
        ruleProvider.vehicleType.toLowerCase(),
      ].some((i) => i.includes(f)),
    )
  })
})

export const referencedRuleProviderNames = computed(() => {
  const seen = new Set<string>()
  const names: string[] = []

  rules.value.forEach((rule) => {
    if (!isProxyRuleEnabled(rule) || !isRuleSetProxyRule(rule)) {
      return
    }

    const providerName = String(rule.payload || '').trim()

    if (!providerName || seen.has(providerName)) {
      return
    }

    seen.add(providerName)
    names.push(providerName)
  })

  return names
})

export const referencedRuleProviderNameSet = computed(() => {
  return new Set(referencedRuleProviderNames.value)
})

export const hasReferencedRuleProviders = computed(() => {
  return referencedRuleProviderNames.value.length > 0
})

export const referencedRuleProviderOrderIndexMap = computed(() => {
  return new Map(referencedRuleProviderNames.value.map((name, index) => [name, index]))
})

export const ruleProviderOrderIndexMap = computed(() => {
  return new Map(ruleProviderOrderList.value.map((name, index) => [name, index]))
})

export const visibleRuleProviderList = computed(() => {
  if (!hasReferencedRuleProviders.value) {
    return []
  }

  return ruleProviderList.value
    .filter((provider) => {
      return referencedRuleProviderNameSet.value.has(provider.name)
    })
    .sort((left, right) => {
      const leftReferencedOrder = referencedRuleProviderOrderIndexMap.value.get(left.name)
      const rightReferencedOrder = referencedRuleProviderOrderIndexMap.value.get(right.name)

      if (leftReferencedOrder !== undefined || rightReferencedOrder !== undefined) {
        return (
          (leftReferencedOrder ?? Number.MAX_SAFE_INTEGER) -
          (rightReferencedOrder ?? Number.MAX_SAFE_INTEGER)
        )
      }

      const leftOrder = ruleProviderOrderIndexMap.value.get(left.name)
      const rightOrder = ruleProviderOrderIndexMap.value.get(right.name)

      if (leftOrder !== undefined || rightOrder !== undefined) {
        return (leftOrder ?? Number.MAX_SAFE_INTEGER) - (rightOrder ?? Number.MAX_SAFE_INTEGER)
      }

      return 0
    })
})

export const isRuleEnabled = (rule: Rule) => {
  if (rule.extra) {
    return !rule.extra.disabled
  }

  return !rule.disabled
}

export const isRuleRefreshRunning = computed(() => {
  return ruleRefreshState.value.isRefreshing
})

export const ruleRefreshDisplayText = computed(() => {
  if (ruleRefreshState.value.scope === 'provider' && ruleRefreshState.value.isRefreshing) {
    return ''
  }

  if (ruleRefreshState.value.isRefreshing && ruleRefreshState.value.phase === 'provider') {
    if (!ruleRefreshState.value.totalProviders) {
      return ''
    }

    return `${ruleRefreshState.value.updatedProviders}/${ruleRefreshState.value.totalProviders}`
  }

  if (ruleRefreshState.value.isRefreshing && ruleRefreshState.value.phase === 'cache') {
    return `${ruleCacheRefreshCount.value || 0}`
  }

  if (ruleCacheTotalRules.value > 0) {
    return `${ruleCacheTotalRules.value}`
  }

  return ''
})

export const fetchRules = async () => {
  const { data: ruleData } = await fetchRulesAPI()
  const { data: providerData } = await fetchRuleProvidersAPI()

  const rawRules = ruleData?.rules || []

  // 1. 判断是否为 sing-box 内核 (sing-box 规则包含 outbound 或 rule_set 等特有属性)
  isSingboxKernel.value = rawRules.some(
    (r: Record<string, unknown>) => 'outbound' in r || 'rule_set' in r,
  )

  // 2. 根据内核类型分别解析
  if (isSingboxKernel.value) {
    // sing-box 走适配器逻辑
    rules.value = normalizeSingboxRules(rawRules)
    ruleProviderList.value = Object.values(normalizeSingboxProviders(providerData?.providers || {}))
  } else {
    // 原有 Clash / Nikki 的标准解析逻辑保持不变
    rules.value = rawRules.map((rule) => {
      const proxy = rule.proxy || ''
      const proxyName = proxy.startsWith('route(') ? proxy.substring(6, proxy.length - 1) : proxy

      return {
        ...rule,
        proxy: proxyName,
      }
    })
    ruleProviderList.value = Object.values(providerData?.providers || {})
  }
}

export const fetchRuleProviders = async () => {
  const { data: providerData } = await fetchRuleProvidersAPI()

  if (isSingboxKernel.value) {
    ruleProviderList.value = Object.values(normalizeSingboxProviders(providerData?.providers || {}))
  } else {
    ruleProviderList.value = Object.values(providerData?.providers || {})
  }
}

export const updateRuleProviderCache = async () => {
  const response = await fetchServerApi('/api/rule-provider-cache/update', {
    method: 'POST',
  })

  if (!response.ok) {
    const errorBody = (await response.json().catch(() => null)) as { message?: string } | null
    throw new Error(errorBody?.message || `Failed to update rule cache: ${response.status}`)
  }

  return (await response.json()) as {
    ok: boolean
    totalProviders: number
    updatedCount: number
    unsupportedCount: number
    totalRules: number
    providerCounts: Record<string, number>
    providerUrls: Record<string, string>
    providerOrder: string[]
    progressRules: number
    cancelled: boolean
    errors: { name: string; url: string; message: string }[]
  }
}

export const cancelRuleProviderCacheUpdate = async () => {
  const response = await fetchServerApi('/api/rule-provider-cache/cancel', {
    method: 'POST',
  })

  if (!response.ok) {
    const errorBody = (await response.json().catch(() => null)) as { message?: string } | null
    throw new Error(errorBody?.message || `Failed to cancel rule cache update: ${response.status}`)
  }

  return (await response.json()) as {
    ok: boolean
  }
}

export const startBackgroundRuleRefresh = async (
  providerName = '',
  providerNames?: string[],
  referencedOnly = false,
) => {
  const response = await fetchServerApi('/api/rule-refresh/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      providerName,
      providerNames,
      referencedOnly,
    }),
  })

  if (!response.ok) {
    const errorBody = (await response.json().catch(() => null)) as { message?: string } | null
    throw new Error(
      errorBody?.message || `Failed to start background rule refresh: ${response.status}`,
    )
  }

  return (await response.json()) as {
    ok: boolean
    started: boolean
    providerName: string
    totalRules: number
    providerCounts: Record<string, number>
    providerUrls: Record<string, string>
    providerOrder: string[]
    progress: {
      isUpdating: boolean
      totalProviders: number
      updatedProviders: number
      totalRules: number
      errors: number
      unsupportedCount: number
      cancelled: boolean
      completed: boolean
    }
    refresh: RuleRefreshState
  }
}

export const cancelBackgroundRuleRefresh = async () => {
  const response = await fetchServerApi('/api/rule-refresh/cancel', {
    method: 'POST',
  })

  if (!response.ok) {
    const errorBody = (await response.json().catch(() => null)) as { message?: string } | null
    throw new Error(
      errorBody?.message || `Failed to cancel background rule refresh: ${response.status}`,
    )
  }

  return (await response.json()) as {
    ok: boolean
    providerName: string
    totalRules: number
    providerCounts: Record<string, number>
    providerUrls: Record<string, string>
    providerOrder: string[]
    progress: {
      isUpdating: boolean
      totalProviders: number
      updatedProviders: number
      totalRules: number
      errors: number
      unsupportedCount: number
      cancelled: boolean
      completed: boolean
    }
    refresh: RuleRefreshState
  }
}

export const fetchRuleProviderCacheStats = async () => {
  const response = await fetchServerApi('/api/rule-provider-cache/stats')

  if (!response.ok) {
    const errorBody = (await response.json().catch(() => null)) as { message?: string } | null
    throw new Error(errorBody?.message || `Failed to fetch rule cache stats: ${response.status}`)
  }

  return (await response.json()) as {
    totalRules: number
    providerCounts: Record<string, number>
    providerUrls: Record<string, string>
    providerOrder: string[]
    progress: {
      isUpdating: boolean
      totalProviders: number
      updatedProviders: number
      totalRules: number
      errors: number
      unsupportedCount: number
      cancelled: boolean
      completed: boolean
    }
    refresh: RuleRefreshState
  }
}

export const applyRuleProviderCacheStats = (stats: {
  totalRules: number
  providerCounts?: Record<string, number>
  providerUrls?: Record<string, string>
  providerOrder?: string[]
  progress?: {
    isUpdating: boolean
    totalProviders: number
    updatedProviders: number
    totalRules: number
    errors: number
    unsupportedCount: number
    cancelled: boolean
    completed: boolean
  }
  refresh?: Partial<RuleRefreshState>
}) => {
  ruleCacheTotalRules.value = stats.totalRules
  ruleProviderLocalCountMap.value = stats.providerCounts || {}
  ruleProviderSourceUrlMap.value = stats.providerUrls || {}
  ruleProviderOrderList.value = stats.providerOrder || []
  ruleRefreshState.value = {
    ...createDefaultRuleRefreshState(),
    ...ruleRefreshState.value,
    ...(stats.refresh || {}),
    totalRules:
      stats.refresh?.totalRules !== undefined ? stats.refresh.totalRules : stats.totalRules,
  }

  if (stats.progress?.isUpdating) {
    isRuleCacheUpdating.value = true
    ruleCacheRefreshCount.value = stats.progress.totalRules || 0
    return
  }

  if (isRuleCacheUpdating.value) {
    ruleCacheRefreshCount.value = 0
  }

  isRuleCacheUpdating.value = false
}

