<template>
  <section class="console-root">
    <!-- Row 1: Task Snapshot + Tool History side by side -->
    <div class="console-row console-row--equal">
      <n-card size="small" embedded title="Task Snapshot">
        <n-descriptions :column="1" size="small" bordered label-placement="top">
          <n-descriptions-item label="Stage">
            <n-tag size="tiny" round :bordered="false" type="info">{{ prettifyStage(task?.current_stage) }}</n-tag>
          </n-descriptions-item>
          <n-descriptions-item label="Decision">
            <div class="row-tags">
              <n-tag size="tiny" round :bordered="false" :type="riskTagType(lastDecision?.risk_level)">
                {{ lastDecision?.tool_name || '—' }}
              </n-tag>
              <n-tag v-if="lastDecision?.source" size="tiny" round :bordered="false" :type="decisionSourceType(lastDecision.source)">
                {{ decisionSourceLabel(lastDecision.source) }}
              </n-tag>
            </div>
          </n-descriptions-item>
          <n-descriptions-item label="Scope">
            <span class="text-ellipsis">{{ (task?.scope || []).join(', ') || 'n/a' }}</span>
          </n-descriptions-item>
          <n-descriptions-item label="Summary">
            <span class="text-ellipsis line-clamp-2">{{ task?.state?.last_summary || 'Waiting…' }}</span>
          </n-descriptions-item>
        </n-descriptions>
      </n-card>

      <n-card size="small" embedded title="Tool History">
        <div v-if="recentActions.length" class="tool-list">
          <div v-for="a in recentActions" :key="a.summary" class="tool-chip">
            <div class="tool-chip__tags">
              <n-tag size="tiny" round :bordered="false" :type="a.success ? 'success' : 'error'">{{ a.tool_name }}</n-tag>
              <span class="tool-chip__stage">{{ a.stage }}</span>
            </div>
            <p class="tool-chip__summary">{{ truncate(a.summary, 80) }}</p>
          </div>
        </div>
        <n-empty v-else description="No tool history" size="small" />
      </n-card>
    </div>

    <!-- Row 2: Hosts + Services side by side -->
    <div class="console-row console-row--equal">
      <n-card size="small" embedded title="Hosts">
        <div v-if="hosts.length" class="host-list">
          <div v-for="host in hosts" :key="host.address" class="host-chip">
            <Shield :size="13" />
            <span>{{ host.address }}</span>
            <n-tag size="tiny" round :bordered="false" type="success">{{ host.status }}</n-tag>
          </div>
        </div>
        <n-empty v-else description="No hosts" size="small" />
      </n-card>

      <n-card size="small" embedded title="Services">
        <div v-if="services.length" class="svc-list">
          <div v-for="svc in services" :key="`${svc.target}-${svc.port}`" class="svc-chip">
            <code class="svc-endpoint">{{ svc.target }}:{{ svc.port }}</code>
            <span class="svc-name">{{ svc.service || '?' }}</span>
            <span class="svc-ver">{{ [svc.product, svc.version].filter(Boolean).join(' ') || '' }}</span>
          </div>
        </div>
        <n-empty v-else description="No services" size="small" />
      </n-card>
    </div>

    <!-- Row 3: Reflection + Hypotheses side by side -->
    <div class="console-row console-row--equal">
      <n-card size="small" embedded title="Reflection">
        <div v-if="lastReflection" class="stack-xs">
          <p class="subtle-text line-clamp-3">{{ lastReflection.summary }}</p>
          <div class="row-tags">
            <n-tag size="tiny" round :bordered="false" type="warning">{{ failureClassLabel(lastReflection.failure_class) }}</n-tag>
            <n-tag v-if="lastReflection.selected_family" size="tiny" round :bordered="false" type="info">{{ lastReflection.selected_family }}</n-tag>
            <n-tag v-for="f in (lastReflection.rejected_families || []).slice(0, 2)" :key="f" size="tiny" round :bordered="false" type="error">{{ f }}</n-tag>
          </div>
          <div v-if="(lastReflection.next_candidates || []).length" class="cand-list">
            <div v-for="c in lastReflection.next_candidates.slice(0, 2)" :key="c.id || c.tool_name" class="cand-chip">
              <n-tag size="tiny" round :bordered="false" :type="riskTagType(c.risk_level)">{{ c.tool_name }}</n-tag>
              <span>{{ c.title }}</span>
            </div>
          </div>
        </div>
        <n-empty v-else description="No reflection" size="small" />
      </n-card>

      <n-card size="small" embedded title="Hypotheses">
        <div v-if="hypotheses.length" class="hypo-list">
          <div v-for="h in hypotheses.slice(0, 6)" :key="h.title" class="hypo-chip">
            <div class="hypo-chip__head">
              <strong class="text-ellipsis">{{ h.title }}</strong>
              <n-tag size="tiny" round :bordered="false">{{ h.status || 'unverified' }}</n-tag>
            </div>
            <p class="subtle-text line-clamp-1">{{ h.rationale }}</p>
          </div>
          <p v-if="hypotheses.length > 6" class="subtle-text" style="text-align:center">+{{ hypotheses.length - 6 }} more</p>
        </div>
        <n-empty v-else description="No hypotheses" size="small" />
      </n-card>
    </div>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import { NCard, NDescriptions, NDescriptionsItem, NEmpty, NTag } from 'naive-ui'
import { Shield } from '@lucide/vue'
import { decisionSourceLabel, decisionSourceType, failureClassLabel, prettifyStage, prettifyStatus, riskTagType, statusTagType } from '../utils/ui'

const props = defineProps({ task: { type: Object, default: null } })

const actions = computed(() => props.task?.state?.actions || [])
const hosts = computed(() => props.task?.state?.hosts || [])
const services = computed(() => props.task?.state?.services || [])
const hypotheses = computed(() => props.task?.state?.hypotheses || [])
const lastDecision = computed(() => props.task?.state?.last_decision || null)
const lastReflection = computed(() => props.task?.state?.last_reflection || null)
const recentActions = computed(() => [...actions.value].reverse().slice(0, 8))

function truncate(s, n) { return !s ? '' : s.length > n ? s.slice(0, n) + '…' : s }
</script>

<style scoped>
.console-root {
  display: flex; flex-direction: column; gap: 16px;
}
.console-row {
  display: grid; gap: 16px; align-items: start;
}
.console-row--equal {
  grid-template-columns: 1fr 1fr;
}
@media (max-width: 768px) {
  .console-row--equal { grid-template-columns: 1fr; }
}

/* Shared utils */
.row-tags { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }
.stack-xs { display: flex; flex-direction: column; gap: 6px; }
.text-ellipsis { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.line-clamp-1 { display: -webkit-box; -webkit-line-clamp: 1; -webkit-box-orient: vertical; overflow: hidden; white-space: normal; }
.line-clamp-2 { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; white-space: normal; }
.line-clamp-3 { display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; white-space: normal; }
.subtle-text { color: #6a7f76; font-size: 12px; margin: 0; }

/* Tool history */
.tool-list { display: flex; flex-direction: column; gap: 6px; }
.tool-chip { padding: 6px 8px; background: rgba(255,255,255,0.025); border-radius: 6px; }
.tool-chip__tags { display: flex; align-items: center; gap: 6px; margin-bottom: 2px; }
.tool-chip__stage { font-size: 11px; color: #6a7f76; }
.tool-chip__summary { font-size: 11px; color: #8a9d93; margin: 0; line-clamp: 1; }

/* Hosts */
.host-list { display: flex; flex-wrap: wrap; gap: 6px; }
.host-chip { display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px; background: rgba(66,211,146,0.08); border: 1px solid rgba(66,211,146,0.15); border-radius: 8px; font-size: 12px; color: #42d392; }

/* Services */
.svc-list { display: flex; flex-direction: column; gap: 4px; }
.svc-chip { display: flex; align-items: center; gap: 8px; padding: 5px 8px; background: rgba(255,255,255,0.02); border-radius: 6px; }
.svc-endpoint { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #42d392; background: rgba(66,211,146,0.1); padding: 1px 5px; border-radius: 3px; }
.svc-name { font-size: 12px; color: #c2d0c8; font-weight: 500; }
.svc-ver { font-size: 11px; color: #6a7f76; margin-left: auto; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 120px; }

/* Candidates */
.cand-list { display: flex; flex-direction: column; gap: 4px; }
.cand-chip { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #8a9d93; }

/* Hypotheses */
.hypo-list { display: flex; flex-direction: column; gap: 4px; }
.hypo-chip { padding: 5px 8px; background: rgba(255,255,255,0.02); border-radius: 6px; }
.hypo-chip__head { display: flex; align-items: center; justify-content: space-between; gap: 6px; margin-bottom: 2px; font-size: 12px; }
</style>
