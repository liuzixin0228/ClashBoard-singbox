<template>
  <RuleCard
    v-if="matchedRule"
    :key="`pen-matched-${matchedRule.index}`"
    :rule="matchedRule"
    :index="matchedRule.index + 1"
  />
  <div class="card">
    <div class="app-card-padding flex flex-col gap-3 text-sm">
      <div class="flex flex-wrap items-center gap-2">
        <BoltIcon class="text-main h-4 w-4 shrink-0" />
        <span class="font-semibold">{{ $t('routePenetrationTitle') }}</span>
        <span class="text-base-content/50 text-xs">{{ result.target }}</span>
      </div>

      <div class="text-base-content/80 flex flex-col gap-1.5 text-xs">
        <div class="flex flex-wrap items-center gap-2">
          <span class="text-base-content/60">{{ $t('routePenetrationLiveRule') }}</span>
          <span class="badge badge-sm">{{ live.rule || '—' }}</span>
          <span
            v-if="live.rulePayload"
            class="font-medium"
          >
            {{ live.rulePayload }}
          </span>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <span class="text-base-content/60">{{ $t('routePenetrationLiveChains') }}</span>
          <template
            v-for="(hop, i) in live.chains"
            :key="`live-${i}`"
          >
            <span class="font-medium">{{ hop }}</span>
            <ChevronRightIcon
              v-if="i < live.chains.length - 1"
              class="text-base-content/25 h-3 w-3"
            />
          </template>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <span class="text-base-content/60">{{ $t('routePenetrationLiveDns') }}</span>
          <span class="font-medium">
            {{ live.destinationIP || '—' }}
            <span
              v-if="live.destinationIP && live.destinationPort"
              class="text-base-content/50"
            >
              :{{ live.destinationPort }}
            </span>
          </span>
          <span
            v-if="live.dnsMode"
            class="badge badge-ghost badge-sm"
          >
            {{ live.dnsMode }}
          </span>
        </div>
      </div>

      <p
        v-if="result.liveError"
        class="text-base-content/50 text-xs"
      >
        {{ $t('routePenetrationLiveNotFound') }}
      </p>
      <p
        v-if="result.preview.matchError"
        class="text-warning text-xs"
      >
        {{ $t('routePenetrationMatchError', { message: result.preview.matchError }) }}
      </p>
      <p
        v-if="result.preview.chainError"
        class="text-warning text-xs"
      >
        {{ $t('routePenetrationChainError', { message: result.preview.chainError }) }}
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  routePenetrationResult,
  type RoutePenetrationLive,
  type RoutePenetrationResponse,
} from '@/store/routePenetration'
import { rules } from '@/store/rules'
import type { Rule } from '@/types'
import { BoltIcon, ChevronRightIcon } from '@heroicons/vue/24/outline'
import { computed } from 'vue'
import RuleCard from '@/components/rules/RuleCard.vue'

const props = defineProps<{
  result: RoutePenetrationResponse
}>()

const result = computed(() => props.result || routePenetrationResult.value)

// 预览命中的规则:优先用规则列表里的原始对象(保留命中次数等展示信息),否则按响应拼一个
const matchedRule = computed<Rule | null>(() => {
  const matched = result.value?.preview.matched

  if (!matched) {
    return null
  }

  const original = rules.value.find((rule) => rule.index === matched.index)

  return (
    original || {
      type: matched.type,
      payload: matched.payload,
      proxy: matched.outbound,
      size: 0,
      uuid: `pen-${matched.index}`,
      index: matched.index,
    }
  )
})

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
    }
  )
})
</script>
