import { fetchServerApi } from '@/store/auth'
import { ref } from 'vue'

export interface RoutePenetrationMatched {
  index: number
  type: string
  payload: string
  outbound: string
}

export interface RoutePenetrationDnsInfo {
  rejected?: boolean
  server: string
  protocol: string
  address: string
  detour: string
  fakeip?: boolean
  isFinal?: boolean
  matchedRule?: { index: number; summary: string } | null
  realServer?: Omit<RoutePenetrationDnsInfo, 'realServer' | 'fakeip'> | null
  clashModes?: {
    mode: string
    rejected: boolean
    server: string
    protocol: string
    address: string
    detour: string
  }[]
}

export interface RoutePenetrationMatchedEntry {
  ruleset: string
  line: number
  value: string
  mode: string
}

export interface RoutePenetrationPreview {
  matched: RoutePenetrationMatched | null
  matchError: string
  finalOutbound: string
  skippedTypes: string[]
  resolvedOutbound: string
  chain: string[]
  chainError: string
  dns: RoutePenetrationDnsInfo | null
  matchedEntry: RoutePenetrationMatchedEntry | null
}

export interface RoutePenetrationLive {
  found: boolean
  id: string
  rule: string
  rulePayload: string
  chains: string[]
  destinationIP: string
  destinationPort: string
  dnsMode: string
  sniffHost: string
  requestScheme: string
  probeVia: string
  requestMs: number
  httpStatus: number
  httpLocation: string
  requestError: string
}

export interface DnsProbeQueryResult {
  ok: boolean
  rcode?: number
  ips: string[]
  ttl?: number
  ms: number
  error?: string
  fakeip?: boolean
}

export interface DnsProbeResult {
  attempted: boolean
  reason?: string
  host?: string
  port?: number
  a?: DnsProbeQueryResult
  aaaa?: DnsProbeQueryResult
}

export interface DnsConfigCache {
  source: string
  configPath: string
  updatedAt: string
  dns: {
    servers: Record<string, unknown>[]
    rules: Record<string, unknown>[]
    final: string
    strategy: string
  }
  dnsInbound: { listen: string; listen_port: number } | null
}

export interface RoutePenetrationDnsAnswer {
  status?: string
  answer?: unknown[]
}

export interface RoutePenetrationResponse {
  target: string
  queryType: 'domain' | 'ip'
  preview: RoutePenetrationPreview
  live: RoutePenetrationLive | null
  liveError: string
  dnsAnswer: { answer?: unknown; ips?: string[]; ms?: number } | null
  dnsProbe?: DnsProbeResult | null
}

export const routePenetrationTarget = ref('')
export const routePenetrationQueriedTarget = ref('')
export const routePenetrationLoading = ref(false)
export const routePenetrationError = ref('')
export const routePenetrationResult = ref<RoutePenetrationResponse | null>(null)
// 模块一:跟随搜索框 debounce 的规则路由预览(不发真实请求)
export const routePreviewLoading = ref(false)
export const routePreviewResult = ref<RoutePenetrationResponse | null>(null)

let latestRequestId = 0
let latestPreviewRequestId = 0

const requestRoutePenetration = async (target: string, live: boolean) => {
  const response = await fetchServerApi('/api/route-penetration', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ target, live }),
  })

  if (!response.ok) {
    const errorBody = (await response.json().catch(() => null)) as { message?: string } | null
    throw new Error(errorBody?.message || `Failed to query route penetration: ${response.status}`)
  }

  return (await response.json()) as RoutePenetrationResponse
}

export const runRoutePenetrationPreview = async (target: string) => {
  const requestId = ++latestPreviewRequestId
  const trimmed = target.trim()

  routePreviewLoading.value = true

  try {
    const data = await requestRoutePenetration(trimmed, false)

    if (requestId !== latestPreviewRequestId) return

    routePreviewResult.value = data
  } catch {
    if (requestId === latestPreviewRequestId) {
      routePreviewResult.value = null
    }
  } finally {
    if (requestId === latestPreviewRequestId) {
      routePreviewLoading.value = false
    }
  }
}

export const runRoutePenetration = async (target: string) => {
  const requestId = ++latestRequestId
  const trimmed = target.trim()

  routePenetrationQueriedTarget.value = trimmed
  routePenetrationLoading.value = true
  routePenetrationError.value = ''

  try {
    const data = await requestRoutePenetration(trimmed, true)

    if (requestId !== latestRequestId) return

    routePenetrationResult.value = data
  } catch (error) {
    if (requestId !== latestRequestId) return

    routePenetrationResult.value = null
    routePenetrationError.value = error instanceof Error ? error.message : String(error)
  } finally {
    if (requestId === latestRequestId) {
      routePenetrationLoading.value = false
    }
  }
}

export const resetRoutePenetration = () => {
  routePenetrationTarget.value = ''
  routePenetrationError.value = ''
  routePenetrationResult.value = null
  routePenetrationLoading.value = false
  routePreviewResult.value = null
  routePreviewLoading.value = false
  latestPreviewRequestId++
}

// ===== 内核运行配置的 DNS 段(规则路由 DNS 预览的数据源) =====

export const dnsConfigCache = ref<DnsConfigCache | null>(null)
export const dnsConfigFetching = ref(false)
export const dnsConfigError = ref('')
// 当前缓存的配置是否已过时(刚刷新过一次就置 false)
const dnsConfigLoadedOnce = ref(false)

export const fetchDnsConfig = async () => {
  const response = await fetchServerApi('/api/dns-config')
  const data = (await response.json()) as { cached: boolean; config: DnsConfigCache | null }

  if (data.config) {
    dnsConfigCache.value = data.config
    dnsConfigLoadedOnce.value = true
  }

  return data
}

export const refreshDnsConfig = async () => {
  if (dnsConfigFetching.value) return

  dnsConfigFetching.value = true
  dnsConfigError.value = ''

  try {
    const response = await fetchServerApi('/api/dns-config/refresh', { method: 'POST' })

    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { message?: string } | null

      throw new Error(body?.message || `Failed to refresh dns config: ${response.status}`)
    }

    const data = (await response.json()) as { config: DnsConfigCache }

    dnsConfigCache.value = data.config
    dnsConfigLoadedOnce.value = true
  } catch (error) {
    dnsConfigError.value = error instanceof Error ? error.message : String(error)
    throw error
  } finally {
    dnsConfigFetching.value = false
  }
}

// 进入规则页时调用:已有缓存直接取,没有缓存则后台补种一次(失败静默,由手动刷新提示)
export const bootstrapDnsConfig = async () => {
  if (dnsConfigLoadedOnce.value || dnsConfigFetching.value) return

  try {
    const data = await fetchDnsConfig()

    if (!data.cached && !dnsConfigCache.value) {
      await refreshDnsConfig()
    }
  } catch {
    // 静默失败:预览处会展示"未读取到 DNS 配置"与刷新按钮
  }
}
