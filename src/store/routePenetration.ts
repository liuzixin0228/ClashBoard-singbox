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
  realServer?: Omit<RoutePenetrationDnsInfo, 'realServer' | 'fakeip'> | null
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
  requestMs: number
  httpStatus: number
  httpLocation: string
  requestError: string
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
  dnsAnswer: { answer?: unknown; ms?: number } | null
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
