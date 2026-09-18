<template>
  <div class="card">
    <div class="app-card-padding flex flex-col gap-3 text-sm">
      <div class="flex flex-wrap items-center gap-2">
        <MagnifyingGlassIcon class="text-base-content/60 h-4 w-4 shrink-0" />
        <span class="font-semibold">{{ $t('routePreviewTitle') }}</span>
        <span class="text-base-content/50 text-xs">· {{ result.target }}</span>
      </div>

      <div class="flex flex-col gap-3">
        <div class="flex items-start gap-3">
          <span class="text-base-content/50 w-10 shrink-0 text-xs leading-6">
            {{ $t('routePenetrationChainExit') }}
          </span>
          <div class="flex min-w-0 flex-wrap items-center gap-1 text-sm">
            <template
              v-for="(hop, i) in result.preview.chain"
              :key="`p-chain-${i}`"
            >
              <ChevronRightIcon
                v-if="i > 0"
                class="text-base-content/25 h-3.5 w-3.5"
              />
              <span class="font-medium">{{ hop }}</span>
            </template>
            <span
              v-if="result.preview.chain.length === 0"
              class="text-base-content/40 text-xs"
            >
              {{ result.preview.matchError ? $t('routePreviewUnknown') : '—' }}
            </span>
          </div>
        </div>

        <div
          v-if="dnsRow"
          class="flex items-start gap-3"
        >
          <span class="text-base-content/50 w-10 shrink-0 text-xs leading-6">
            {{ $t('routePreviewDns') }}
          </span>
          <div class="flex min-w-0 flex-wrap items-center gap-1.5 text-sm">
            <span
              v-if="dnsRow.rejected"
              class="badge badge-error badge-sm"
            >
              {{ $t('routePreviewDnsBlocked') }}
            </span>
            <template v-else>
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
          </div>
        </div>

        <div
          v-if="result.preview.matched"
          class="flex items-start gap-3"
        >
          <span class="text-base-content/50 w-10 shrink-0 text-xs leading-6">
            {{ $t('routePreviewRule') }}
          </span>
          <div class="flex min-w-0 flex-col gap-1">
            <div class="flex min-w-0 flex-wrap items-center gap-1.5 text-sm">
              <span class="badge badge-success badge-sm">
                {{ $t('routePreviewRuleHit', { index: result.preview.matched.index + 1 }) }}
              </span>
              <span class="truncate font-medium">{{ result.preview.matched.payload }}</span>
            </div>
            <div
              v-if="matchedEntry"
              class="flex min-w-0 flex-wrap items-center gap-1.5 text-xs"
            >
              <span class="badge badge-ghost badge-sm">{{ matchedEntryLabel }}</span>
              <span
                v-if="matchedEntry.value"
                class="text-success font-medium"
              >
                {{ matchedEntry.value }}
              </span>
              <span class="text-base-content/50">{{ matchedEntry.ruleset }}</span>
            </div>
          </div>
        </div>

        <p
          v-if="result.preview.matchError"
          class="text-base-content/50 text-xs"
        >
          {{ $t('routePenetrationMatchError', { message: result.preview.matchError }) }}
        </p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  routePreviewResult,
  type RoutePenetrationDnsInfo,
  type RoutePenetrationMatchedEntry,
  type RoutePenetrationResponse,
} from '@/store/routePenetration'
import { MagnifyingGlassIcon, ChevronRightIcon } from '@heroicons/vue/24/outline'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
  result: RoutePenetrationResponse
}>()

const result = computed(() => props.result || routePreviewResult.value!)

const { t } = useI18n()

const dnsRow = computed<RoutePenetrationDnsInfo | null>(() => {
  const dns = result.value?.preview.dns

  if (!dns) return null
  // fakeip 模式展示真实上游服务器
  if (dns.fakeip && dns.realServer) return dns.realServer
  return dns
})

const matchedEntry = computed<RoutePenetrationMatchedEntry | null>(
  () => result.value?.preview.matchedEntry ?? null,
)

const matchedEntryLabel = computed(() => {
  const entry = matchedEntry.value

  if (!entry) return ''

  if (entry.mode === 'suffix') return t('routePreviewModeSuffix')
  if (entry.mode === 'keyword') return t('routePreviewModeKeyword')
  if (entry.mode === 'domain') return t('routePreviewModeDomain')
  return t('routePreviewModeLine', { line: entry.line })
})
</script>
