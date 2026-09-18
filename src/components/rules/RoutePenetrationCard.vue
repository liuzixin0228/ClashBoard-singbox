<template>
  <div class="card">
    <div class="app-card-padding flex flex-col gap-3 text-sm">
      <div class="flex flex-wrap items-center gap-2">
        <BoltIcon class="text-main h-4 w-4 shrink-0" />
        <span class="font-semibold">{{ $t('routePenetrationTitle') }}</span>
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
          class="btn btn-circle btn-ghost btn-xs ml-auto -mr-1"
          :title="$t('close')"
          @click="resetRoutePenetration()"
        >
          <XMarkIcon class="h-4 w-4" />
        </button>
      </div>

      <div class="flex flex-col gap-3">
        <div class="flex items-start gap-3">
          <span class="text-base-content/50 w-10 shrink-0 text-xs leading-6">
            {{ $t('routePenetrationChainExit') }}
          </span>
          <div class="flex min-w-0 flex-col gap-0.5">
            <div class="flex min-w-0 flex-wrap items-center gap-1 text-sm">
              <template
                v-for="(hop, i) in live.chains"
                :key="`l-chain-${i}`"
              >
                <ChevronRightIcon
                  v-if="i > 0"
                  class="text-base-content/25 h-3.5 w-3.5"
                />
                <span class="font-medium">{{ hop }}</span>
              </template>
            </div>
            <div
              v-if="live.found"
              class="text-base-content/60 flex min-w-0 flex-wrap items-center gap-2 text-xs"
            >
              <span class="font-medium">http://{{ result.target }}/</span>
              <span v-if="live.httpStatus">
                HTTP {{ live.httpStatus }} ·
                {{
                  httpStatusLabel
                }}
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

        <div class="flex items-start gap-3">
          <span class="text-base-content/50 w-10 shrink-0 text-xs leading-6">
            {{ $t('routePreviewDns') }}
          </span>
          <div class="flex min-w-0 flex-col gap-0.5">
            <div class="flex min-w-0 flex-wrap items-center gap-1.5 text-sm">
              <template v-if="dnsRow">
                <span
                  class="badge badge-sm"
                  :class="dnsRow.detour ? 'badge-info' : 'badge-ghost'"
                >
                  {{ dnsRow.detour ? $t('routePreviewDnsProxy') : $t('routePreviewDnsDirect') }}
                </span>
                <span class="font-medium">{{ dnsRow.server }}</span>
                <span
                  v-if="dnsRow.protocol"
                  class="text-base-content/60 text-xs"
                >
                  {{ dnsRow.protocol }} {{ dnsRow.address }}
                </span>
                <span
                  v-if="dnsRow.detour"
                  class="text-base-content/60 text-xs"
                >
                  {{ $t('routePreviewDnsVia') }} {{ dnsRow.detour }}
                </span>
              </template>
              <span
                v-if="live.dnsMode"
                class="badge badge-ghost badge-sm"
              >
                {{ live.dnsMode }}
              </span>
              <span
                v-if="live.found && result.dnsAnswer?.ms"
                class="text-base-content/60 text-xs tabular-nums"
              >
                {{ result.dnsAnswer.ms }}ms
              </span>
            </div>
            <div class="flex min-w-0 flex-wrap items-center gap-1.5 text-sm">
              <span class="text-base-content/60 text-xs">
                {{ $t('routePenetrationLiveDns') }}
              </span>
              <span class="font-medium">
                {{ live.destinationIP || '—' }}
                <span
                  v-if="live.destinationIP && live.destinationPort"
                  class="text-base-content/50"
                >
                  :{{ live.destinationPort }}
                </span>
              </span>
            </div>
          </div>
        </div>

        <p
          v-if="result.liveError"
          class="text-base-content/50 text-xs"
        >
          {{ $t('routePenetrationLiveNotFound') }}
        </p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  resetRoutePenetration,
  routePenetrationLoading,
  routePenetrationResult,
  type RoutePenetrationLive,
  type RoutePenetrationResponse,
} from '@/store/routePenetration'
import { ArrowPathIcon, BoltIcon, ChevronRightIcon, XMarkIcon } from '@heroicons/vue/24/outline'
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
      requestMs: 0,
      httpStatus: 0,
      httpLocation: '',
      requestError: '',
    }
  )
})

// DNS 行展示真实上游服务器(fakeip 模式下也一致)
const dnsRow = computed(() => {
  const dns = result.value?.preview.dns

  if (!dns) return null
  if (dns.fakeip && dns.realServer) return dns.realServer
  if (dns.rejected) return null
  return dns
})

const { t } = useI18n()

// 2xx/3xx 视为可达(带 Location 是跳转),其余状态如实标注异常
const httpStatusLabel = computed(() => {
  const status = live.value.httpStatus

  if (status >= 200 && status < 400) {
    return live.value.httpLocation ? t('routePenetrationHttpRedirect') : t('routePenetrationHttpOk')
  }

  return t('routePenetrationHttpError', { status })
})
</script>
