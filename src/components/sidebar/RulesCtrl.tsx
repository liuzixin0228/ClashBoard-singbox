import { useCtrlsBar } from '@/composables/useCtrlsBar'
import { showNotification } from '@/helper/notification'
import {
  applyRuleProviderCacheStats,
  cancelBackgroundRuleRefresh,
  fetchRuleProviderCacheStats,
  isRuleCacheUpdating,
  isRuleRefreshRunning,
  ruleCacheRefreshCount,
  ruleCacheTotalRules,
  ruleProviderSourceUrlMap,
  rulesFilter,
  startBackgroundRuleRefresh,
} from '@/store/rules'
import {
  disconnectOnRuleDisable,
  displayLatencyInRule,
  displayNowNodeInRule,
} from '@/store/settings'
import {
  routePenetrationLoading,
  runRoutePenetration,
} from '@/store/routePenetration'
import { ArrowPathIcon, BoltIcon, WrenchScrewdriverIcon } from '@heroicons/vue/24/outline'
import { computed, defineComponent, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import DialogWrapper from '../common/DialogWrapper.vue'
import TextInput from '../common/TextInput.vue'

export default defineComponent({
  name: 'RulesCtrl',
  setup() {
    const { t } = useI18n()
    const settingsModel = ref(false)
    const isRefreshingRules = ref(false)
    const { isLargeCtrlsBar } = useCtrlsBar()

    const referencedProviderRefreshNames = computed(() => {
      // 服务端规则源配置里能同步到的全部规则集名(与核心的 /providers/rules 无关)
      return Object.keys(ruleProviderSourceUrlMap.value)
    })

    const handlerClickSyncRuleSource = async () => {
      if (isRefreshingRules.value) return

      isRefreshingRules.value = true

      try {
        if (isRuleRefreshRunning.value || isRuleCacheUpdating.value) {
          const result = await cancelBackgroundRuleRefresh()
          applyRuleProviderCacheStats(result)
          showNotification({
            key: 'ruleRefreshCompletedTip',
            content: 'ruleRefreshStopped',
            type: 'alert-warning',
            timeout: 2000,
          })
          return
        }

        // sing-box 的 /providers/rules 可能为空(源:0),此时同步全部规则源而不是拒绝
        ruleCacheRefreshCount.value = 0
        const result = await startBackgroundRuleRefresh(
          '',
          referencedProviderRefreshNames.value,
          true,
        )
        applyRuleProviderCacheStats(result)
        const latestStats = await fetchRuleProviderCacheStats()
        applyRuleProviderCacheStats(latestStats)
      } catch (error) {
        showNotification({
          key: 'ruleRefreshCompletedTip',
          content: error instanceof Error ? error.message : String(error),
          type: 'alert-error',
          timeout: 3000,
        })
      } finally {
        isRefreshingRules.value = false
      }
    }

    const handlerClickRoutePenetration = async () => {
      if (routePenetrationLoading.value) return

      const target = rulesFilter.value.trim()

      if (!target) {
        showNotification({
          key: 'routePenetrationInputRequired',
          content: 'routePenetrationInputRequired',
          type: 'alert-warning',
          timeout: 2000,
        })
        return
      }

      try {
        await runRoutePenetration(target)
      } catch (error) {
        showNotification({
          key: 'routePenetrationError',
          content: error instanceof Error ? error.message : String(error),
          type: 'alert-error',
          timeout: 3000,
        })
      }
    }

    return () => {
      const searchInput = (
        <TextInput
          class={isLargeCtrlsBar.value ? 'w-80' : 'min-w-0 flex-1'}
          v-model={rulesFilter.value}
          placeholder={t('ruleSearchPlaceholder')}
          clearable={true}
        />
      )

      const penetrationButton = (
        <button
          class="btn btn-circle btn-sm shrink-0"
          title={t('routePenetrationTitle')}
          onClick={handlerClickRoutePenetration}
        >
          {routePenetrationLoading.value ? (
            <span class="loading loading-spinner loading-xs" />
          ) : (
            <BoltIcon class="h-4 w-4" />
          )}
        </button>
      )

      const syncButton = (
        <button
          class="btn btn-circle btn-sm shrink-0"
          title={t('ruleRefreshSummary', {
            rules: `${ruleCacheTotalRules.value || 0}`,
            sources: `${referencedProviderRefreshNames.value.length}`,
          })}
          onClick={handlerClickSyncRuleSource}
        >
          <ArrowPathIcon
            class={[
              'h-4 w-4',
              (isRefreshingRules.value ||
                isRuleRefreshRunning.value ||
                isRuleCacheUpdating.value) &&
                'animate-spin',
            ]}
          />
        </button>
      )

      const settingsModal = (
        <>
          <button
            class="btn btn-circle btn-sm"
            onClick={() => (settingsModel.value = true)}
          >
            <WrenchScrewdriverIcon class="h-4 w-4" />
          </button>
          <DialogWrapper
            v-model={settingsModel.value}
            title={t('ruleSettings')}
          >
            <div class="flex flex-col gap-4 p-2 text-sm">
              <div class="flex items-center gap-2">
                {t('displaySelectedNode')}
                <input
                  class="toggle"
                  type="checkbox"
                  v-model={displayNowNodeInRule.value}
                />
              </div>
              <div class="flex items-center gap-2">
                {t('displayLatencyNumber')}
                <input
                  class="toggle"
                  type="checkbox"
                  v-model={displayLatencyInRule.value}
                />
              </div>
              <div class="flex items-center gap-2">
                {t('disconnectOnRuleDisable')}
                <input
                  class="toggle"
                  type="checkbox"
                  v-model={disconnectOnRuleDisable.value}
                />
              </div>
            </div>
          </DialogWrapper>
        </>
      )

      const content = (
        <div class="app-card-padding flex w-full min-w-0 items-center gap-2">
          {searchInput}
          <div class="ml-auto flex shrink-0 items-center gap-2">
            {penetrationButton}
            {syncButton}
            {settingsModal}
          </div>
        </div>
      )

      return <div class="ctrls-bar">{content}</div>
    }
  },
})
