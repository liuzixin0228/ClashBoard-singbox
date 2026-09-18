<template>
  <div class="relative flex size-full min-h-0 flex-col overflow-hidden">
    <RulesCtrl />
    <template v-if="!isVirtualScroller">
      <div
        class="min-h-0 flex-1 overflow-x-hidden overflow-y-auto"
        :style="padding"
      >
        <div class="app-page-gap app-page-padding flex flex-col">
          <RoutePreviewCard
            v-if="routePreviewResult"
            :result="routePreviewResult"
          />
          <div
            v-else-if="routePreviewLoading"
            class="card app-card-padding text-sm"
          >
            <span class="loading loading-spinner loading-xs mr-2 align-middle" />
            {{ t('routePreviewLoading') }}
          </div>
          <div
            v-if="routePenetrationError"
            class="alert alert-error app-card-padding text-sm"
          >
            <ExclamationTriangleIcon class="h-4 w-4 shrink-0" />
            <span class="min-w-0 break-all">{{ routePenetrationError }}</span>
          </div>
          <RoutePenetrationCard
            v-if="routePenetrationResult"
            :result="routePenetrationResult"
            @retest="retestRoutePenetration"
          />
          <RuleCard
            v-for="rule in renderRules"
            :key="`${rule.type}-${rule.payload}-${rule.proxy}`"
            :rule="rule"
            :index="rules.indexOf(rule) + 1"
          />
        </div>
      </div>
    </template>
    <template v-else>
      <div class="app-page-margin shrink-0">
        <RoutePreviewCard
          v-if="routePreviewResult"
          :result="routePreviewResult"
        />
        <div
          v-if="routePenetrationError"
          class="alert alert-error app-card-padding text-sm"
        >
          <ExclamationTriangleIcon class="h-4 w-4 shrink-0" />
          <span class="min-w-0 break-all">{{ routePenetrationError }}</span>
        </div>
        <RoutePenetrationCard
          v-if="routePenetrationResult"
          :result="routePenetrationResult"
          @retest="retestRoutePenetration"
        />
      </div>
      <VirtualScroller
        class="min-h-0 flex-1"
        :style="virtualScrollerStyle"
        :data="renderRules"
        :size="84"
      >
        <template #default="{ item: rule }: { item: Rule }">
          <RuleCard
            :key="`${rule.type}-${rule.payload}-${rule.proxy}`"
            :rule="rule"
            :index="rules.indexOf(rule) + 1"
          />
        </template>
      </VirtualScroller>
    </template>
    <ProxyGroupRulePenetrationDialog />
  </div>
</template>

<script setup lang="ts">
import VirtualScroller from '@/components/common/VirtualScroller.vue'
import ProxyGroupRulePenetrationDialog from '@/components/proxies/ProxyGroupRulePenetrationDialog.vue'
import RoutePenetrationCard from '@/components/rules/RoutePenetrationCard.vue'
import RoutePreviewCard from '@/components/rules/RoutePreviewCard.vue'
import RuleCard from '@/components/rules/RuleCard.vue'
import RulesCtrl from '@/components/sidebar/RulesCtrl.tsx'
import { usePaddingForViews } from '@/composables/paddingViews'
import { fetchProxies } from '@/store/proxies'
import {
  bootstrapDnsConfig,
  resetRoutePenetration,
  routePenetrationError,
  routePenetrationQueriedTarget,
  routePenetrationResult,
  routePreviewLoading,
  routePreviewResult,
  runRoutePenetration,
  runRoutePenetrationPreview,
} from '@/store/routePenetration'
import {
  applyRuleProviderCacheStats,
  fetchRuleProviderCacheStats,
  fetchRules,
  isRuleCacheUpdating,
  renderRules,
  ruleCacheRefreshCount,
  ruleCacheTotalRules,
  ruleProviderList,
  rules,
  rulesFilter,
  updateRuleProviderCache,
} from '@/store/rules'
import type { Rule } from '@/types'
import { ExclamationTriangleIcon } from '@heroicons/vue/24/outline'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const retestRoutePenetration = () => {
  const target = routePenetrationQueriedTarget.value || rulesFilter.value.trim()

  if (target) {
    void runRoutePenetration(target)
  }
}

const autoRuleCacheBootstrapAttempted = ref(false)

void Promise.allSettled([fetchRules(), fetchProxies()]).then(async () => {
  // 真实路由检测的预览依赖规则缓存,首次进入时自动补种
  try {
    if (
      !autoRuleCacheBootstrapAttempted.value &&
      ruleProviderList.value.length > 0 &&
      ruleCacheTotalRules.value === 0 &&
      !isRuleCacheUpdating.value
    ) {
      autoRuleCacheBootstrapAttempted.value = true
      isRuleCacheUpdating.value = true
      ruleCacheRefreshCount.value = 0

      const result = await updateRuleProviderCache()
      applyRuleProviderCacheStats(result)
    } else {
      applyRuleProviderCacheStats(await fetchRuleProviderCacheStats())
    }
  } catch {
    isRuleCacheUpdating.value = false
  }

  // DNS 预览依赖内核运行配置的 dns 段缓存,首次进入时自动读取(失败静默)
  void bootstrapDnsConfig()
})

let previewTimer: ReturnType<typeof setTimeout> | undefined

watch(rulesFilter, (value) => {
  // 搜索只负责过滤列表;检测类结果一律清除,规则路由预览 800ms 防抖后自动查询
  if (previewTimer) clearTimeout(previewTimer)
  resetRoutePenetration()

  const trimmed = value.trim()

  if (!trimmed) return

  previewTimer = setTimeout(() => {
    void runRoutePenetrationPreview(trimmed)
  }, 800)
})

onBeforeUnmount(() => {
  if (previewTimer) clearTimeout(previewTimer)
  // 离开规则页即清掉检测结果,避免下次进入时残留
  resetRoutePenetration()
})

const { padding, paddingTop } = usePaddingForViews({
  offsetTop: 0,
  offsetBottom: 8,
})
const virtualScrollerStyle = computed(() => ({
  paddingTop: `${paddingTop.value}px`,
}))

const isVirtualScroller = computed(() => {
  return renderRules.value.length > 200
})
</script>
