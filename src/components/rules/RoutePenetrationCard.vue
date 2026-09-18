<template>
  <div class="card">
    <div class="app-card-padding flex flex-col gap-3 text-sm">
      <div class="border-base-content/10 flex flex-wrap items-center gap-2 border-b pb-2.5">
        <BoltIcon class="text-main h-4 w-4 shrink-0" />
        <span class="font-semibold">{{ $t('routePenetrationTitle') }}</span>
        <span
          v-if="live.found"
          class="badge badge-success badge-sm gap-1"
        >
          <CheckCircleIcon class="h-3 w-3" />
          {{ $t('routePenetrationCaptured') }}
        </span>
        <span
          v-else-if="result.liveError"
          class="badge badge-warning badge-sm gap-1"
        >
          <ExclamationTriangleIcon class="h-3 w-3" />
          {{ $t('routePenetrationNotCaptured') }}
        </span>
        <button
          class="btn btn-ghost btn-xs gap-1"
          :disabled="routePenetrationLoading"
          @click="$emit('retest')"
        >
          <ArrowPathIcon
            class="h-3.5 w-3.5"
            :class="{ 'animate-spin': routePenetrationLoading }"
          />
          {{ $t('routePenetrationRetest') }}
        </button>
        <button
          class="btn btn-circle btn-ghost btn-xs -mr-1 ml-auto"
          :title="$t('close')"
          @click="resetRoutePenetration()"
        >
          <XMarkIcon class="h-4 w-4" />
        </button>
      </div>

      <div class="flex flex-col gap-3">
        <div class="flex items-start gap-3">
          <div class="flex w-12 shrink-0 flex-col items-center gap-1">
            <div
              class="bg-primary/10 text-primary flex size-7 items-center justify-center rounded-lg"
            >
              <ArrowsRightLeftIcon class="h-4 w-4" />
            </div>
            <span class="text-base-content/45 text-[10px] leading-none">
              {{ $t('routePenetrationChainExit') }}
            </span>
          </div>
          <div class="flex min-w-0 flex-1 flex-col gap-1">
            <div class="flex min-w-0 flex-wrap items-center gap-1">
              <template
                v-for="(hop, i) in live.chains"
                :key="`l-chain-${i}`"
              >
                <ChevronRightIcon
                  v-if="i > 0"
                  class="text-base-content/25 h-3.5 w-3.5"
                />
                <span
                  class="rounded-md border px-2 py-0.5 text-xs font-medium"
                  :class="chainChipClass(i, live.chains.length)"
                >
                  {{ hop }}
                </span>
              </template>
              <span
                v-if="live.chains.length === 0"
                class="text-base-content/40 text-xs"
              >
                —
              </span>
            </div>
            <div
              v-if="live.found"
              class="text-base-content/60 flex min-w-0 flex-wrap items-center gap-2 text-xs"
            >
              <span class="font-mono"
                >{{ live.requestScheme || 'http' }}://{{ result.target }}/</span
              >
              <span
                v-if="live.probeVia"
                class="badge badge-ghost badge-sm"
              >
                {{ probeViaLabel }}
              </span>
              <span
                v-if="live.httpStatus"
                class="badge badge-sm gap-1"
                :class="httpStatusBadgeClass"
              >
                <CheckCircleIcon
                  v-if="httpStatusPillIcon === 'ok'"
                  class="h-3 w-3"
                />
                <ArrowUturnRightIcon
                  v-else-if="httpStatusPillIcon === 'redirect'"
                  class="h-3 w-3"
                />
                <ExclamationTriangleIcon
                  v-else
                  class="h-3 w-3"
                />
                HTTP {{ live.httpStatus }} · {{ httpStatusLabel }}
              </span>
              <span
                v-if="live.requestMs"
                class="tabular-nums"
              >
                {{ live.requestMs }}ms
              </span>
              <span
                v-if="live.requestError"
                class="text-warning"
              >
                {{ live.requestError }}
              </span>
            </div>
          </div>
        </div>

        <div
          v-if="result.queryType === 'domain'"
          class="flex items-start gap-3"
        >
          <div class="flex w-12 shrink-0 flex-col items-center gap-1">
            <div class="bg-info/10 text-info flex size-7 items-center justify-center rounded-lg">
              <GlobeAltIcon class="h-4 w-4" />
            </div>
            <span class="text-base-content/45 text-[10px] leading-none">
              {{ $t('routePreviewDns') }}
            </span>
          </div>
          <div class="flex min-w-0 flex-1 flex-col gap-1">
            <div class="flex min-w-0 flex-wrap items-center gap-1.5">
              <template v-if="dnsRow">
                <span
                  v-if="dnsRow.rejected"
                  class="badge badge-error badge-sm"
                >
                  {{ $t('routePreviewDnsBlocked') }}
                </span>
                <template v-else>
                  <span
                    v-if="!dnsRow.fakeip"
                    class="badge badge-sm"
                    :class="dnsRow.detour ? 'badge-info' : 'badge-ghost'"
                  >
                    {{ dnsRow.detour ? $t('routePreviewDnsProxy') : $t('routePreviewDnsDirect') }}
                  </span>
                  <span
                    v-if="dnsRow.fakeip"
                    class="badge badge-warning badge-sm"
                  >
                    fakeip
                  </span>
                  <span
                    class="border-base-content/10 bg-base-content/5 rounded-md border px-2 py-0.5 text-xs font-semibold"
                  >
                    {{ dnsRow.server }}
                  </span>
                  <span
                    v-if="dnsRow.protocol && !dnsRow.fakeip"
                    class="text-base-content/60 font-mono text-xs"
                  >
                    {{ dnsRow.protocol }} {{ dnsRow.address }}
                  </span>
                  <span
                    v-if="dnsRow.detour"
                    class="text-base-content/60 text-xs"
                  >
                    {{ $t('routePreviewDnsVia') }} {{ dnsRow.detour }}
                  </span>
                  <span
                    v-if="dnsRow.isFinal"
                    class="badge badge-ghost badge-sm"
                  >
                    {{ $t('routePreviewDnsFinal') }}
                  </span>
                  <span
                    v-else-if="dnsRow.matchedRule"
                    class="badge badge-success badge-sm"
                  >
                    {{ $t('routePreviewDnsRuleHit', { index: dnsRow.matchedRule.index }) }}
                  </span>
                </template>
              </template>
              <span
                v-if="dnsModeLabel"
                class="badge badge-ghost badge-sm"
              >
                {{ dnsModeLabel }}
              </span>
            </div>
            <div
              v-if="dnsRow?.fakeip && !dnsRow.rejected && dnsRow.realServer"
              class="text-base-content/60 flex min-w-0 flex-wrap items-center gap-1.5 text-xs"
            >
              <span class="text-base-content/45">{{ $t('routePreviewDnsRealUpstream') }}</span>
              <span class="font-medium">{{ dnsRow.realServer.server }}</span>
              <span
                v-if="dnsRow.realServer.protocol"
                class="text-base-content/60 font-mono"
              >
                {{ dnsRow.realServer.protocol }} {{ dnsRow.realServer.address }}
              </span>
              <span
                v-if="dnsRow.realServer.detour"
                class="text-base-content/60"
              >
                {{ $t('routePreviewDnsVia') }} {{ dnsRow.realServer.detour }}
              </span>
            </div>
          </div>
        </div>

        <div
          v-if="showRealDnsPanel"
          class="bg-base-content/5 border-base-content/10 flex flex-col gap-2 rounded-lg border p-2.5"
        >
          <div class="flex items-center gap-2">
            <div
              class="bg-secondary/10 text-secondary flex size-6 items-center justify-center rounded-md"
            >
              <SignalIcon class="h-3.5 w-3.5" />
            </div>
            <span class="text-base-content/70 text-xs font-semibold">
              {{ $t('routePenetrationRealDnsTitle') }}
            </span>
            <span
              v-if="dnsProbe?.attempted"
              class="text-base-content/40 font-mono text-xs"
            >
              {{ dnsProbe.host }}:{{ dnsProbe.port }}
            </span>
          </div>
          <div class="text-base-content/60 flex flex-col gap-1.5 pl-8 text-xs">
            <div class="flex min-w-0 flex-wrap items-center gap-1.5">
              <span class="text-base-content/45">{{ $t('routePenetrationLiveDns') }}</span>
              <span class="font-medium tabular-nums">
                {{ live.destinationIP || '—' }}
                <span
                  v-if="live.destinationIP && live.destinationPort"
                  class="text-base-content/50"
                >
                  :{{ live.destinationPort }}
                </span>
              </span>
            </div>
            <div
              v-if="dnsProbe?.attempted"
              class="flex min-w-0 flex-wrap items-center gap-1.5"
            >
              <span class="text-base-content/45">{{ $t('routePenetrationDnsProbeSource') }}</span>
              <span
                v-for="probeRow in dnsProbeRows"
                :key="`dns-probe-${probeRow.label}`"
                class="border-base-content/10 bg-base-background/60 rounded-md border px-2 py-0.5"
              >
                <span class="font-semibold">{{ probeRow.label }}</span>
                <template v-if="probeRow.result?.ips.length">
                  <span class="font-mono tabular-nums">{{ probeRow.result.ips.join(', ') }}</span>
                  <span
                    v-if="probeRow.result.fakeip"
                    class="text-warning"
                  >
                    ({{ $t('routePenetrationDnsFakeIp') }})
                  </span>
                  <span class="text-base-content/50 tabular-nums"
                    >· {{ probeRow.result.ms }}ms</span
                  >
                </template>
                <template v-else>
                  <span class="text-base-content/40">
                    {{ $t('routePenetrationDnsNoAnswer') }}
                  </span>
                  <span
                    v-if="probeRow.result?.error"
                    class="text-base-content/40"
                  >
                    · {{ probeRow.result.error }}
                  </span>
                </template>
              </span>
            </div>
            <div
              v-else-if="dnsProbe && !dnsProbe.attempted"
              class="text-base-content/40"
            >
              {{ $t('routePenetrationDnsProbeSkipped', { reason: dnsProbe.reason || '' }) }}
            </div>
            <div
              v-if="dnsAnswerIps.length"
              class="flex min-w-0 flex-wrap items-center gap-1.5"
            >
              <span class="text-base-content/45">{{ $t('routePenetrationDnsAnswerSource') }}</span>
              <span class="font-mono font-medium tabular-nums">{{ dnsAnswerIps.join(', ') }}</span>
              <span
                v-if="result.dnsAnswer?.ms"
                class="text-base-content/50 tabular-nums"
              >
                · {{ result.dnsAnswer.ms }}ms
              </span>
            </div>
          </div>
        </div>

        <div
          v-if="result.liveError"
          class="alert alert-warning py-2 text-xs"
        >
          <ExclamationTriangleIcon class="h-4 w-4 shrink-0" />
          <span>{{ $t('routePenetrationLiveNotFound') }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  resetRoutePenetration,
  routePenetrationLoading,
  routePenetrationResult,
  type DnsProbeQueryResult,
  type RoutePenetrationDnsInfo,
  type RoutePenetrationLive,
  type RoutePenetrationResponse,
} from '@/store/routePenetration'
import {
  ArrowPathIcon,
  ArrowsRightLeftIcon,
  ArrowUturnRightIcon,
  BoltIcon,
  CheckCircleIcon,
  ChevronRightIcon,
  ExclamationTriangleIcon,
  GlobeAltIcon,
  SignalIcon,
  XMarkIcon,
} from '@heroicons/vue/24/outline'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
  result: RoutePenetrationResponse
}>()

defineEmits<{
  retest: []
}>()

const result = computed(() => props.result || routePenetrationResult.value!)

const live = computed<RoutePenetrationLive>(() => {
  return (
    result.value?.live ?? {
      found: false,
      id: '',
      rule: '',
      rulePayload: '',
      chains: [],
      destinationIP: '',
      destinationPort: '',
      dnsMode: '',
      sniffHost: '',
      requestScheme: '',
      probeVia: '',
      requestMs: 0,
      httpStatus: 0,
      httpLocation: '',
      requestError: '',
    }
  )
})

const dnsRow = computed<RoutePenetrationDnsInfo | null>(() => result.value?.preview.dns ?? null)

const dnsProbe = computed(() => result.value?.dnsProbe ?? null)

const dnsProbeRows = computed<{ label: string; result?: DnsProbeQueryResult }[]>(() => {
  const probe = dnsProbe.value

  if (!probe?.attempted) return []

  return [
    { label: 'A', result: probe.a },
    { label: 'AAAA', result: probe.aaaa },
  ]
})

const dnsAnswerIps = computed<string[]>(() => {
  const ips = result.value?.dnsAnswer?.ips

  return Array.isArray(ips) ? ips : []
})

const showRealDnsPanel = computed(() => {
  if (result.value?.queryType !== 'domain') return false

  return Boolean(dnsProbe.value || dnsAnswerIps.value.length || live.value.found)
})

const { t } = useI18n()

// 内核连接元数据里的 dnsMode 是英文枚举,已知值本地化,未知值原样展示
const dnsModeLabel = computed(() => {
  const mode = live.value.dnsMode.toLowerCase()

  if (!mode) return ''
  if (mode === 'fakeip') return 'fakeip'

  return mode === 'normal' ? t('dnsModeNormal') : live.value.dnsMode
})

const probeViaLabel = computed(() => {
  if (live.value.probeVia === 'local-proxy') return t('routePenetrationProbeViaLocal')
  if (live.value.probeVia === 'core-proxy') return t('routePenetrationProbeViaCore')

  return t('routePenetrationProbeViaDirect')
})

// 2xx/3xx 视为可达(带 Location 是跳转),其余状态如实标注异常
const httpStatusLabel = computed(() => {
  const status = live.value.httpStatus

  if (status >= 200 && status < 400) {
    return live.value.httpLocation ? t('routePenetrationHttpRedirect') : t('routePenetrationHttpOk')
  }

  return t('routePenetrationHttpError', { status })
})

const httpStatusBadgeClass = computed(() => {
  const status = live.value.httpStatus

  return status >= 200 && status < 400 ? 'badge-success' : 'badge-warning'
})

const httpStatusPillIcon = computed(() => {
  const status = live.value.httpStatus

  if (status >= 200 && status < 400) {
    return live.value.httpLocation ? 'redirect' : 'ok'
  }

  return 'error'
})

// 链路末端是实际出口节点,用主题色高亮让视线第一时间落点
const chainChipClass = (index: number, total: number) => {
  if (total > 0 && index === total - 1) {
    return 'border-primary/25 bg-primary/10 text-primary font-semibold'
  }

  return 'border-base-content/10 bg-base-content/5'
}
</script>
