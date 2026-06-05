<template>
  <section class="stack-lg">
    <div class="section-header">
      <div>
        <p class="section-kicker">Console</p>
        <h3>执行概览</h3>
      </div>
      <n-tag round size="small" :bordered="false" :type="statusTagType(task?.status)">
        {{ prettifyStatus(task?.status) }}
      </n-tag>
    </div>

    <div class="detail-grid">
      <n-card size="small" embedded title="任务快照">
        <n-descriptions :column="1" size="small" bordered>
          <n-descriptions-item label="当前阶段">
            {{ prettifyStage(task?.current_stage) }}
          </n-descriptions-item>
          <n-descriptions-item label="当前决策">
            <div class="decision-line">
              <span>{{ lastDecision?.tool_name || '未决策' }}</span>
              <n-tag
                v-if="lastDecision?.source"
                size="small"
                round
                :bordered="false"
                :type="decisionSourceType(lastDecision.source)"
              >
                {{ decisionSourceLabel(lastDecision.source) }}
              </n-tag>
            </div>
          </n-descriptions-item>
          <n-descriptions-item label="目标范围">
            {{ (task?.scope || []).join(', ') || 'n/a' }}
          </n-descriptions-item>
          <n-descriptions-item label="最近摘要">
            {{ task?.state?.last_summary || '等待执行。' }}
          </n-descriptions-item>
        </n-descriptions>
      </n-card>

      <div class="stack">
        <n-card size="small" embedded title="最近反思">
          <div v-if="lastReflection" class="stack">
            <div class="decision-line">
              <strong>{{ lastReflection.summary }}</strong>
              <n-tag
                size="small"
                round
                :bordered="false"
                :type="decisionSourceType(lastReflection.source)"
              >
                {{ decisionSourceLabel(lastReflection.source) }}
              </n-tag>
            </div>
            <div class="inline-tags">
              <n-tag size="small" round :bordered="false" type="warning">
                {{ failureClassLabel(lastReflection.failure_class) }}
              </n-tag>
              <n-tag
                v-if="lastReflection.selected_family"
                size="small"
                round
                :bordered="false"
                type="info"
              >
                {{ lastReflection.selected_family }}
              </n-tag>
              <n-tag
                v-for="family in lastReflection.rejected_families || []"
                :key="family"
                size="small"
                round
                :bordered="false"
                type="error"
              >
                reject: {{ family }}
              </n-tag>
            </div>
            <p v-if="lastReflection.family_switch_reason" class="subtle-text">
              {{ lastReflection.family_switch_reason }}
            </p>
            <div v-if="(lastReflection.next_candidates || []).length" class="stack">
              <p class="subtle-text">下一跳候选</p>
              <div class="candidate-list">
                <div
                  v-for="candidate in lastReflection.next_candidates"
                  :key="candidate.id || `${candidate.tool_name}-${candidate.title}`"
                  class="candidate-card"
                >
                  <div class="candidate-card__head">
                    <strong>{{ candidate.title }}</strong>
                    <n-tag size="small" round :bordered="false" :type="riskTagType(candidate.risk_level)">
                      {{ candidate.tool_name }}
                    </n-tag>
                  </div>
                  <p class="subtle-text">{{ candidate.rationale }}</p>
                  <div v-if="(candidate.family_details || []).length" class="inline-tags">
                    <n-tag
                      v-for="family in candidate.family_details"
                      :key="family.id"
                      size="small"
                      round
                      :bordered="false"
                      type="info"
                    >
                      {{ family.title }}
                    </n-tag>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <n-empty v-else description="暂无反思结果" />
        </n-card>

        <n-card size="small" embedded title="工具历史">
          <div v-if="actions.length" class="stack">
            <div v-for="action in actions.slice().reverse().slice(0, 6)" :key="`${action.tool_name}-${action.summary}`" class="artifact-row">
              <div>
                <strong>{{ action.tool_name }}</strong>
                <p class="subtle-text">{{ action.summary }}</p>
              </div>
              <n-tag size="small" round :bordered="false" :type="action.success ? 'success' : 'error'">
                {{ action.stage }}
              </n-tag>
            </div>
          </div>
          <n-empty v-else description="暂无工具历史" />
        </n-card>

        <n-card size="small" embedded title="漏洞假设">
          <div v-if="hypotheses.length" class="stack">
            <div v-for="item in hypotheses" :key="item.title" class="finding-row">
              <div class="finding-row__head">
                <strong>{{ item.title }}</strong>
                <n-tag size="small" round :bordered="false" :type="riskTagType(item.status)">
                  {{ item.status || 'unverified' }}
                </n-tag>
              </div>
              <p class="subtle-text">{{ item.rationale }}</p>
            </div>
          </div>
          <n-empty v-else description="暂无假设" />
        </n-card>
      </div>

      <div class="stack">
        <n-card size="small" embedded title="发现主机">
          <div v-if="hosts.length" class="inline-tags">
            <n-tag v-for="host in hosts" :key="host.address" round :bordered="false" type="info">
              {{ host.address }} · {{ host.status }}
            </n-tag>
          </div>
          <n-empty v-else description="暂无主机结果" />
        </n-card>

        <n-card size="small" embedded title="服务清单">
          <div v-if="services.length" class="stack">
            <div v-for="service in services" :key="`${service.target}-${service.port}`" class="artifact-row">
              <div>
                <strong>{{ service.target }}:{{ service.port }}</strong>
                <p class="subtle-text">
                  {{ service.service }} {{ service.product }} {{ service.version }}
                </p>
              </div>
            </div>
          </div>
          <n-empty v-else description="暂无服务结果" />
        </n-card>
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import {
  NCard,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NTag,
} from 'naive-ui'

import {
  decisionSourceLabel,
  decisionSourceType,
  failureClassLabel,
  prettifyStage,
  prettifyStatus,
  riskTagType,
  statusTagType,
} from '../utils/ui'

const props = defineProps({
  task: {
    type: Object,
    default: null,
  },
})

const actions = computed(() => props.task?.state?.actions || [])
const hosts = computed(() => props.task?.state?.hosts || [])
const services = computed(() => props.task?.state?.services || [])
const hypotheses = computed(() => props.task?.state?.hypotheses || [])
const lastDecision = computed(() => props.task?.state?.last_decision || null)
const lastReflection = computed(() => props.task?.state?.last_reflection || null)
</script>
