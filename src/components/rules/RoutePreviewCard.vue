<template>
  <div class="card">
    <div class="app-card-padding flex flex-col gap-3 text-sm">
      <div class="border-base-content/10 flex flex-wrap items-center gap-2 border-b pb-2.5">
        <MagnifyingGlassIcon class="text-base-content/60 h-4 w-4 shrink-0" />
        <span class="font-semibold">{{ $t('routePreviewTitle') }}</span>
        <span class="badge badge-ghost badge-sm font-mono">
          {{ result.target }}
        </span>
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
                v-for="(hop, i) in result.preview.chain"
                :key="`p-chain-${i}`"
              >
                <ChevronRightIcon
                  v-if="i > 0"
                  class="text-base-content/25 h-3.5 w-3.5"
                />
                <span
                  class="rounded-md border px-2 py-0.5 text-xs font-medium"
                  :class="chainChipClass(i, result.preview.chain.length)"
                >
                  {{ hop }}
                </span>
              </template>
              <span
                v-if="result.preview.chain.length === 0"
                class="text-base-content/40 text-xs"
              >
                {{ result.preview.matchError ? $t('routePreviewUnknown') : '—' }}
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
                  <span
                    v-if="dnsRow.matchedRule?.summary"
                    class="text-base-content/50 text-xs"
                  >
                    {{ dnsRow.matchedRule.summary }}
                  </span>
                </template>
              </template>
              <span
                v-else-if="!dnsConfigCache"
                class="text-base-content/50 text-xs"
              >
                {{ $t('routePreviewDnsMissing') }}
              </span>
              <button
                class="btn btn-ghost btn-xs gap-1"
                :title="$t('routePreviewDnsRefresh')"
                @click="refreshDnsConfigThenRePreview"
              >
                <ArrowPathIcon
                  class="h-3.5 w-3.5"
                  :class="{ 'animate-spin': dnsConfigFetching }"
                />
                <span
                  v-if="!dnsConfigCache"
                  class="text-xs"
                >
                  {{ $t('routePreviewDnsRefresh') }}
                </span>
              </button>
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
              <span
                v-if="dnsRow.realServer.isFinal"
                class="badge badge-ghost badge-xs"
              >
                {{ $t('routePreviewDnsFinal') }}
              </span>
              <span
                v-else-if="dnsRow.realServer.matchedRule"
                class="badge badge-success badge-xs"
              >
                {{ $t('routePreviewDnsRuleHit', { index: dnsRow.realServer.matchedRule.index }) }}
              </span>
            </div>
            <div
              v-if="dnsRow?.clashModes?.length"
              class="text-base-content/60 flex min-w-0 flex-wrap items-center gap-1.5 text-xs"
            >
              <span class="text-base-content/45">{{ $t('routePreviewDnsClashModeNotes') }}</span>
              <template
                v-for="note in dnsRow.clashModes"
                :key="`dns-mode-${note.mode}`"
              >
                <span
                  class="border-base-content/10 bg-base-content/5 rounded-md border px-2 py-0.5"
                  :title="note.server ? `${note.mode} → ${note.server}` : note.mode"
                >
                  {{ note.mode }} →
                  <template v-if="note.rejected">{{ $t('routePreviewDnsBlocked') }}</template>
                  <template v-else>{{ note.server || '—' }}</template>
                </span>
              </template>
            </div>
          </div>
        </div>

        <div class="flex items-start gap-3">
          <div class="flex w-12 shrink-0 flex-col items-center gap-1">
            <div
              class="bg-success/10 text-success flex size-7 items-center justify-center rounded-lg"
            >
              <FunnelIcon class="h-4 w-4" />
            </div>
            <span class="text-base-content/45 text-[10px] leading-none">
              {{ $t('routePreviewRule') }}
            </span>
          </div>
          <div class="flex min-w-0 flex-1 flex-col gap-1">
            <div
              v-if="result.preview.matched"
              class="flex min-w-0 flex-wrap items-center gap-1.5"
            >
              <span class="badge badge-success badge-sm">
                {{ $t('routePreviewRuleHit', { index: result.preview.matched.index + 1 }) }}
              </span>
              <span class="truncate font-medium">{{ result.preview.matched.payload }}</span>
            </div>
            <div
              v-else-if="!result.preview.matchError && result.preview.finalOutbound"
              class="flex min-w-0 flex-wrap items-center gap-1.5"
            >
              <span class="badge badge-ghost badge-sm">
                {{ $t('routePreviewNoRuleMatched') }}
              </span>
              <span class="text-base-content/50 text-xs">
                {{ $t('routePreviewFallToFinal', { outbound: result.preview.finalOutbound }) }}
              </span>
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
import { showNotification } from '@/helper/notification'
import {
  dnsConfigCache,
  dnsConfigFetching,
  refreshDnsConfig,
  routePreviewResult,
  runRoutePenetrationPreview,
  type RoutePenetrationDnsInfo,
  type RoutePenetrationMatchedEntry,
  type RoutePenetrationResponse,
} from '@/store/routePenetration'
import { rulesFilter } from '@/store/rules'
import {
  ArrowPathIcon,
  ArrowsRightLeftIcon,
  ChevronRightIcon,
  FunnelIcon,
  GlobeAltIcon,
  MagnifyingGlassIcon,
} from '@heroicons/vue/24/outline'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
  result: RoutePenetrationResponse
}>()

const result = computed(() => props.result || routePreviewResult.value!)

const { t } = useI18n()

const dnsRow = computed<RoutePenetrationDnsInfo | null>(() => result.value?.preview.dns ?? null)

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

// 链路末端是实际出口节点,用主题色高亮让视线第一时间落点
const chainChipClass = (index: number, total: number) => {
  if (total > 0 && index === total - 1) {
    return 'border-primary/25 bg-primary/10 text-primary font-semibold'
  }

  return 'border-base-content/10 bg-base-content/5'
}

const refreshDnsConfigThenRePreview = async () => {
  try {
    await refreshDnsConfig()
  } catch (error) {
    showNotification({
      key: 'dnsConfigRefreshFailed',
      content: error instanceof Error ? error.message : String(error),
      type: 'alert-error',
      timeout: 3000,
    })
    return
  }

  const target = rulesFilter.value.trim() || result.value?.target

  if (target) {
    void runRoutePenetrationPreview(target)
  }
}
</script>
