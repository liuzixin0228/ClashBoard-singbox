import { fetchServerApi } from '@/store/auth'
import { ref } from 'vue'

export interface RoutePenetrationMatched {
  index: number
  type: string
  payload: string
  outbound: string
}

export interface RoutePenetrationPreview {
  matched: RoutePenetrationMatched | null
  matchError: string
  finalOutbound: string
  skippedTypes: string[]
  resolvedOutbound: string
  chain: string[]
  chainError: string
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
  dnsAnswer: RoutePenetrationDnsAnswer | null
}

export const routePenetrationTarget = ref('')
export const routePenetrationQueriedTarget = ref('')
export const routePenetrationLoading = ref(false)
export const routePenetrationError = ref('')
export const routePenetrationResult = ref<RoutePenetrationResponse | null>(null)

let latestRequestId = 0

export const runRoutePenetration = async (target: string) => {
  const requestId = ++latestRequestId
  const trimmed = target.trim()

  routePenetrationQueriedTarget.value = trimmed
  routePenetrationLoading.value = true
  routePenetrationError.value = ''

  try {
    const response = await fetchServerApi('/api/route-penetration', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ target: trimmed }),
    })

    if (!response.ok) {
      const errorBody = (await response.json().catch(() => null)) as { message?: string } | null
      throw new Error(errorBody?.message || `Failed to query route penetration: ${response.status}`)
    }

    const data = (await response.json()) as RoutePenetrationResponse

    if (requestId !== latestRequestId) {
      return
    }

    routePenetrationResult.value = data
  } catch (error) {
    if (requestId !== latestRequestId) {
      return
    }

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
}
