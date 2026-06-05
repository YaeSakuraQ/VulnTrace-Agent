<template>
  <n-card size="small" embedded :bordered="false" class="api-balance-card">
    <template #header>
      <div class="api-balance-header">
        <div class="api-balance-title">
          <Zap :size="16" class="api-icon" />
          <span>LLM Usage</span>
        </div>
        <n-tag size="small" round :bordered="false" :type="onlineStatus ? 'success' : 'error'">
          {{ onlineStatus ? 'Online' : 'Offline' }}
        </n-tag>
      </div>
    </template>

    <!-- Provider & Model -->
    <div class="api-info-row">
      <span class="api-info-label">Provider</span>
      <span class="api-info-value">{{ provider }}</span>
    </div>
    <div class="api-info-row">
      <span class="api-info-label">Model</span>
      <span class="api-info-value">{{ model }}</span>
    </div>

    <!-- Divider -->
    <n-divider style="margin: 8px 0" />

    <!-- Cost Stats -->
    <div class="api-stats-grid">
      <div class="api-stat">
        <span class="api-stat-label">Today</span>
        <strong class="api-stat-value">{{ fmtCurrency(dailyCost) }}</strong>
      </div>
      <div class="api-stat">
        <span class="api-stat-label">This Month</span>
        <strong class="api-stat-value">{{ fmtCurrency(monthlyCost) }}</strong>
      </div>
      <div class="api-stat">
        <span class="api-stat-label">Requests</span>
        <strong class="api-stat-value">{{ totalRequests }}</strong>
      </div>
      <div class="api-stat">
        <span class="api-stat-label">Tokens</span>
        <strong class="api-stat-value">{{ fmtTokens(totalTokens) }}</strong>
      </div>
    </div>

    <!-- Token Usage Bar -->
    <div v-if="tokenLimit > 0" class="token-bar-section">
      <div class="token-bar-header">
        <span class="subtle-text">Monthly Quota</span>
        <span class="subtle-text">{{ fmtTokens(monthlyTokens) }} / {{ fmtTokens(tokenLimit) }}</span>
      </div>
      <n-progress
        type="line"
        :percentage="tokenUsagePercent"
        :color="tokenUsagePercent > 90 ? '#e88080' : tokenUsagePercent > 70 ? '#f0a020' : '#42d392'"
        :height="6"
        :border-radius="3"
        :show-indicator="false"
        processing="false"
      />
    </div>

    <!-- Recent Cost Trend -->
    <n-divider style="margin: 8px 0" />
    <div class="trend-header">
      <span class="subtle-text">Recent calls</span>
      <span class="subtle-text">{{ recentCalls.length }} calls</span>
    </div>
    <div v-if="recentCalls.length" class="recent-calls-list">
      <div
        v-for="(call, i) in recentCalls.slice(0, 5)"
        :key="i"
        class="recent-call-row"
      >
        <div class="recent-call-info">
          <n-tag size="tiny" round :bordered="false" :type="callTypeTag(call.type)">
            {{ call.type }}
          </n-tag>
          <span class="recent-call-endpoint">{{ call.endpoint }}</span>
        </div>
        <span class="recent-call-cost">{{ fmtCurrency(call.cost) }}</span>
      </div>
    </div>
    <n-empty v-else description="No recent API calls" size="small" />
  </n-card>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import { NCard, NDivider, NEmpty, NProgress, NTag } from 'naive-ui'
import { Zap } from '@lucide/vue'
import { fetchApiUsage } from '../api/tasks'

const onlineStatus = ref(true)
const provider = ref('DeepSeek')
const model = ref('deepseek-v4-flash')
const dailyCost = ref(0.024)
const monthlyCost = ref(0.38)
const totalRequests = ref(47)
const totalTokens = ref(284000)
const monthlyTokens = ref(284000)
const tokenLimit = ref(1000000)
const recentCalls = ref([
  { type: 'plan', endpoint: 'choose_action', cost: 0.0012 },
  { type: 'reflect', endpoint: 'reflect_result', cost: 0.0008 },
  { type: 'plan', endpoint: 'choose_action', cost: 0.0015 },
  { type: 'classify', endpoint: 'mode_classification', cost: 0.0006 },
  { type: 'plan', endpoint: 'choose_action', cost: 0.0011 },
])

const tokenUsagePercent = computed(() =>
  tokenLimit.value > 0 ? Math.min(100, Math.round((monthlyTokens.value / tokenLimit.value) * 100)) : 0
)

function fmtCurrency(v) { return '$' + (v || 0).toFixed(4) }
function fmtTokens(v) {
  if (v >= 1_000_000) return (v / 1_000_000).toFixed(1) + 'M'
  if (v >= 1_000) return (v / 1_000).toFixed(1) + 'K'
  return String(v)
}
function callTypeTag(type) {
  const map = { plan: 'info', reflect: 'warning', classify: 'success', execute: 'default' }
  return map[type] || 'default'
}

// Poll for real usage data if available
onMounted(async () => {
  try {
    const usage = await fetchApiUsage()
    if (usage) {
      provider.value = usage.provider || provider.value
      model.value = usage.model || model.value
      dailyCost.value = usage.daily_cost || dailyCost.value
      monthlyCost.value = usage.monthly_cost || monthlyCost.value
      totalRequests.value = usage.total_requests || totalRequests.value
      totalTokens.value = usage.total_tokens || totalTokens.value
      monthlyTokens.value = usage.monthly_tokens || monthlyTokens.value
      if (usage.recent_calls) recentCalls.value = usage.recent_calls
      onlineStatus.value = usage.online !== false
    }
  } catch { /* use mock data on failure */ }
})
</script>

<style scoped>
.api-balance-card {
  border: 1px solid rgba(66, 211, 146, 0.15);
  background: linear-gradient(135deg, rgba(66, 211, 146, 0.04) 0%, transparent 50%);
}
.api-balance-header {
  display: flex; align-items: center; justify-content: space-between; width: 100%;
}
.api-balance-title {
  display: flex; align-items: center; gap: 6px; font-weight: 600; font-size: 13px; color: #c2d0c8;
}
.api-icon { color: #42d392; flex-shrink: 0; }
.api-info-row {
  display: flex; justify-content: space-between; align-items: center; padding: 2px 0;
}
.api-info-label { font-size: 12px; color: #6a7f76; }
.api-info-value { font-size: 12px; color: #c2d0c8; font-family: 'JetBrains Mono', monospace; }
.api-stats-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 4px;
}
.api-stat {
  text-align: center; padding: 6px 4px; background: rgba(255,255,255,0.03); border-radius: 6px;
}
.api-stat-label { display: block; font-size: 10px; color: #6a7f76; text-transform: uppercase; letter-spacing: 0.5px; }
.api-stat-value { display: block; font-size: 15px; font-weight: 700; color: #c2d0c8; margin-top: 2px; }
.token-bar-section { margin-top: 4px; }
.token-bar-header { display: flex; justify-content: space-between; margin-bottom: 4px; font-size: 11px; }
.trend-header { display: flex; justify-content: space-between; margin-bottom: 6px; }
.recent-calls-list { display: flex; flex-direction: column; gap: 4px; }
.recent-call-row { display: flex; align-items: center; justify-content: space-between; padding: 3px 0; }
.recent-call-info { display: flex; align-items: center; gap: 6px; }
.recent-call-endpoint { font-size: 11px; color: #8a9d93; font-family: 'JetBrains Mono', monospace; }
.recent-call-cost { font-size: 11px; color: #6a7f76; font-family: 'JetBrains Mono', monospace; }
.subtle-text { color: #6a7f76; font-size: 12px; }
</style>
