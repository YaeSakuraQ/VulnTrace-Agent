<template>
  <section class="stack-lg">
    <div class="section-header">
      <div>
        <p class="section-kicker">Console</p>
        <h3>Execution Overview</h3>
      </div>
      <n-tag round size="small" :bordered="false" :type="statusTagType(task?.status)">
        {{ prettifyStatus(task?.status) }}
      </n-tag>
    </div>

    <div class="detail-grid">
      <!-- Left column: Task Snapshot + Reflections -->
      <div class="stack">
        <n-card size="small" embedded title="Task Snapshot">
          <n-descriptions :column="1" size="small" bordered label-placeplacement="top">
            <n-descriptions-item label="Stage">
              <n-tag size="tiny" round :bordered="false" type="info">
                {{ prettifyStage(task?.current_stage) }}
              </n-tag>
            </n-descriptions-item>
            <n-descriptions-item label="Decision">
              <div class="decision-line">
                <n-tag size="tiny" round :bordered="false" :type="riskTagType(lastDecision?.risk_level)">
                  {{ lastDecision?.tool_name || '—' }}
                </n-tag>
                <n-tag v-if="lastDecision?.source" size="tiny" round :bordered="false" :type="decisionSourceType(lastDecision.source)">
                  {{ decisionSourceLabel(lastDecision.source) }}
                </n-tag>
              </div>
            </n-descriptions-item>
            <n-descriptions-item label="Scope">
              <span class="ellipsis-text">{{ (task?.scope || []).join(', ') || 'n/a' }}</span>
            </n-descriptions-item>
            <n-descriptions-item label="Last Summary">
              <span class="ellipsis-text line-clamp-2">
                {{ task?.state?.last_summary || 'Waiting for execution…' }}
              </span>
            </n-descriptions-item>
          </n-descriptions>
        </n-card>

        <n-card size="small" embedded title="Latest Reflection">
          <div v-if="lastReflection" class="stack-sm">
            <p class="subtle-text">{{ lastReflection.summary }}</p>
            <div class="inline-tags">
              <n-tag size="tiny" round :bordered="false" type="warning">
                {{ failureClassLabel(lastReflection.failure_class) }}
              </n-tag>
              <n-tag v-if="lastReflection.selected_family" size="tiny" round :bordered="false" type="info">
                {{ lastReflection.selected_family }}
              </n-tag>
              <n-tag
                v-for="f in (lastReflection.rejected_families || []).slice(0, 3)"
                :key="f" size="tiny" round :bordered="false" type="error"
              >{{ f }}</n-tag>
              <n-tag v-if="(lastReflection.rejected_families || []).length > 3" size="tiny" round :bordered="false" type="default">
                +{{ lastReflection.rejected_families.length - 3 }}
              </n-tag>
            </div>
            <div v-if="(lastReflection.next_candidates || []).length" class="candidate-list">
              <div
                v-for="c in lastReflection.next_candidates.slice(0, 3)"
                :key="c.id || c.tool_name"
                class="candidate-chip"
              >
                <n-tag size="tiny" round :bordered="false" :type="riskTagType(c.risk_level)">
                  {{ c.tool_name }}
                </n-tag>
                <span class="candidate-chip__title">{{ c.title }}</span>
              </div>
            </div>
          </div>
          <n-empty v-else description="No reflection yet" size="small" />
        </n-card>
      </div>

      <!-- Middle column: Tool History + Hypotheses -->
      <div class="stack">
        <n-card size="small" embedded title="Tool History">
          <div v-if="recentActions.length" class="stack-sm">
            <div
              v-for="action in recentActions"
              :key="action.summary"
              class="tool-row"
            >
              <div class="tool-row__info">
                <div class="tool-row__head">
                  <n-tag size="tiny" round :bordered="false" :type="action.success ? 'success' : 'error'">
                    {{ action.tool_name }}
                  </n-tag>
                  <n-tag size="tiny" round :bordered="false" type="default">
                    {{ action.stage }}
                  </n-tag>
                </div>
                <p class="tool-row__summary">{{ truncate(action.summary, 100) }}</p>
              </div>
            </div>
          </div>
          <n-empty v-else description="No tool history yet" size="small" />
        </n-card>

        <n-card size="small" embedded title="Hypotheses">
          <div v-if="hypotheses.length" class="stack-sm">
            <div v-for="item in hypotheses.slice(0, 8)" :key="item.title" class="hypothesis-row">
              <div class="hypothesis-row__head">
                <strong class="ellipsis-text">{{ item.title }}</strong>
                <n-tag size="tiny" round :bordered="false">
                  {{ item.status || 'unverified' }}
                </n-tag>
              </div>
              <p class="subtle-text line-clamp-2">{{ item.rationale }}</p>
            </div>
            <p v-if="hypotheses.length > 8" class="subtle-text" style="text-align:center">
              +{{ hypotheses.length - 8 }} more hypotheses
            </p>
          </div>
          <n-empty v-else description="No hypotheses yet" size="small" />
        </n-card>
      </div>

      <!-- Right column: Hosts + Services -->
      <div class="stack">
        <n-card size="small" embedded title="Hosts">
          <div v-if="hosts.length" class="hosts-grid">
            <div v-for="host in hosts" :key="host.address" class="host-badge">
              <Shield :size="13" />
              <span>{{ host.address }}</span>
              <n-tag size="tiny" round :bordered="false" type="success">{{ host.status }}</n-tag>
            </div>
          </div>
          <n-empty v-else description="No hosts yet" size="small" />
        </n-card>

        <n-card size="small" embedded title="Services">
          <div v-if="services.length" class="stack-sm">
            <div v-for="svc in services" :key="`${svc.target}-${svc.port}`" class="service-row">
              <div class="service-row__endpoint">
                <code class="endpoint-code">{{ svc.target }}:{{ svc.port }}</code>
                <span class="service-name">{{ svc.service || 'unknown' }}</span>
              </div>
              <span class="subtle-text service-version">
                {{ [svc.product, svc.version].filter(Boolean).join(' ') || '—' }}
              </span>
            </div>
          </div>
          <n-empty v-else description="No services yet" size="small" />
        </n-card>

        <ApiBalancePanel />
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import { NCard, NDescriptions, NDescriptionsItem, NEmpty, NTag } from 'naive-ui'
import { Shield } from '@lucide/vue'

import ApiBalancePanel from './ApiBalancePanel.vue'
import {
  decisionSourceLabel, decisionSourceType, failureClassLabel,
  prettifyStage, prettifyStatus, riskTagType, statusTagType,
} from '../utils/ui'

const props = defineProps({ task: { type: Object, default: null } })

const actions = computed(() => props.task?.state?.actions || [])
const hosts = computed(() => props.task?.state?.hosts || [])
const services = computed(() => props.task?.state?.services || [])
const hypotheses = computed(() => props.task?.state?.hypotheses || [])
const lastDecision = computed(() => props.task?.state?.last_decision || null)
const lastReflection = computed(() => props.task?.state?.last_reflection || null)
const recentActions = computed(() => [...actions.value].reverse().slice(0, 8))

function truncate(str, max) {
  if (!str) return ''
  return str.length > max ? str.slice(0, max) + '…' : str
}
</script>

<style scoped>
.decision-line {
  display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
}
.inline-tags {
  display: flex; align-items: center; gap: 4px; flex-wrap: wrap;
}
.ellipsis-text {
  display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.line-clamp-2 {
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
  white-space: normal;
}
.stack-sm { display: flex; flex-direction: column; gap: 8px; }

/* Tool rows */
.tool-row {
  padding: 6px 8px; background: rgba(255,255,255,0.02); border-radius: 6px; border: 1px solid rgba(255,255,255,0.04);
}
.tool-row__head {
  display: flex; align-items: center; gap: 4px; margin-bottom: 2px;
}
.tool-row__summary {
  font-size: 12px; color: #6a7f76; margin: 0;
  display: -webkit-box; -webkit-line-clamp: 1; -webkit-box-orient: vertical; overflow: hidden;
}

/* Hypothesis rows */
.hypothesis-row {
  padding: 6px 8px; background: rgba(255,255,255,0.02); border-radius: 6px;
}
.hypothesis-row__head {
  display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 4px;
}

/* Candidate chips */
.candidate-list {
  display: flex; flex-direction: column; gap: 6px;
}
.candidate-chip {
  display: flex; align-items: center; gap: 6px;
}
.candidate-chip__title {
  font-size: 12px; color: #8a9d93; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1;
}

/* Hosts */
.hosts-grid {
  display: flex; flex-wrap: wrap; gap: 6px;
}
.host-badge {
  display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px;
  background: rgba(66,211,146,0.08); border: 1px solid rgba(66,211,146,0.15);
  border-radius: 8px; font-size: 13px; color: #42d392;
}

/* Services */
.service-row {
  padding: 6px 8px; background: rgba(255,255,255,0.02); border-radius: 6px;
}
.service-row__endpoint {
  display: flex; align-items: center; gap: 8px; margin-bottom: 2px;
}
.endpoint-code {
  font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #42d392;
  background: rgba(66,211,146,0.1); padding: 2px 6px; border-radius: 4px;
}
.service-name {
  font-size: 13px; color: #c2d0c8; font-weight: 500;
}
.service-version {
  font-family: 'JetBrains Mono', monospace; font-size: 11px;
}
</style>
