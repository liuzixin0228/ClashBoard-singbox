<template>
  <div class="relative flex size-full min-h-0 flex-col overflow-hidden">
    <RulesCtrl />
    <template v-if="!isVirtualScroller">
      <div
        class="min-h-0 flex-1 overflow-x-hidden overflow-y-auto"
        :style="padding"
      >
        <div class="app-page-gap app-page-padding flex flex-col">
          <RoutePenetrationCard
            v-if="routePenetrationResult"
            :result="routePenetrationResult"
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
      <div
        v-if="routePenetrationResult"
        class="app-page-margin shrink-0"
      >
        <RoutePenetrationCard :result="routePenetrationResult" />
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
import RuleCard from '@/components/rules/RuleCard.vue'
import RulesCtrl from '@/components/sidebar/RulesCtrl.tsx'
import { usePaddingForViews } from '@/composables/paddingViews'
import { fetchProxies } from '@/store/proxies'
import {
  resetRoutePenetration,
  routePenetrationQueriedTarget,
  routePenetrationResult,
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
import { computed, ref, watch } from 'vue'

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
})

watch(rulesFilter, () => {
  // 搜索内容变化后,上一轮真实路由检测结果即过期,清掉避免张冠李戴
  if (
    routePenetrationResult.value &&
    rulesFilter.value.trim() !== routePenetrationQueriedTarget.value
  ) {
    resetRoutePenetration()
  }
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
