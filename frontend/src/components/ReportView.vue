<template>
  <section class="stack-lg">
    <div class="section-header">
      <div>
        <p class="section-kicker">Report</p>
        <h3>结果呈现</h3>
      </div>
      <n-tag v-if="report?.path" round size="small" :bordered="false" type="success">
        {{ fileNameFromPath(report.path) }}
      </n-tag>
    </div>

    <div class="stats-grid compact">
      <div class="metric-tile">
        <span class="metric-label">已确认</span>
        <strong>{{ confirmedFindingCount }}</strong>
      </div>
      <div class="metric-tile">
        <span class="metric-label">PoC</span>
        <strong>{{ pocs.length }}</strong>
      </div>
      <div class="metric-tile">
        <span class="metric-label">证据</span>
        <strong>{{ artifacts.length }}</strong>
      </div>
      <div class="metric-tile">
        <span class="metric-label">审批</span>
        <strong>{{ approvals.length }}</strong>
      </div>
    </div>

    <n-tabs type="line" animated default-value="rendered">
      <n-tab-pane name="rendered" tab="完整报告">
        <n-card size="small" embedded class="report-document-card">
          <template #header>
            <div class="card-header-inline">
              <div>
                <strong>渲染后的 Markdown 报告</strong>
                <p class="subtle-text">
                  {{ relativeArtifactPath(report?.path || '') || '报告尚未生成' }}
                </p>
              </div>
            </div>
          </template>

          <article v-if="report?.markdown" class="report-document" v-html="sanitizedHtml"></article>
          <n-empty v-else description="报告尚未生成" />
        </n-card>
      </n-tab-pane>

      <n-tab-pane name="presentation" tab="摘要 / 证据">
        <div class="detail-grid">
          <div class="stack-lg">
            <n-card title="确认发现" size="small" embedded>
              <div v-if="findings.length" class="stack">
                <div v-for="finding in findings" :key="`${finding.title}-${finding.evidence_summary}`" class="finding-row">
                  <div class="finding-row__head">
                    <strong>{{ finding.title }}</strong>
                    <div class="inline-tags">
                      <n-tag size="small" round :bordered="false" :type="riskTagType(finding.confidence)">
                        {{ finding.confidence }}
                      </n-tag>
                      <n-tag size="small" round :bordered="false" :type="riskTagType(finding.severity)">
                        {{ finding.severity }}
                      </n-tag>
                    </div>
                  </div>
                  <p class="subtle-text">{{ finding.evidence_summary }}</p>
                </div>
              </div>
              <n-empty v-else description="暂无发现" />
            </n-card>

            <n-card title="PoC Chain" size="small" embedded>
              <template v-if="pocs.length">
                <n-alert
                  v-if="!directPocs.length"
                  type="info"
                  :show-icon="true"
                  style="margin-bottom: 12px"
                >
                  Synthesized from confirmed findings. Re-run report generation to persist PoC records.
                </n-alert>
                <n-card
                  v-for="poc in pocs"
                  :key="`${poc.id}-${poc.url}`"
                  size="small"
                  class="poc-card"
                >
                  <template #header>
                    <div class="card-header-inline">
                      <div>
                        <strong>{{ poc.title }}</strong>
                        <p class="subtle-text">{{ poc.module }}</p>
                      </div>
                      <n-tag size="small" round :bordered="false" :type="riskTagType(poc.status)">
                        {{ poc.status }}
                      </n-tag>
                    </div>
                  </template>

                  <div class="stack">
                    <div class="poc-meta">
                      <span>{{ poc.method }} {{ poc.path || poc.url }}</span>
                      <span>{{ fileNameFromPath((poc.evidence_files || [])[0]) }}</span>
                    </div>

                    <div v-if="(poc.success_evidence || []).length" class="inline-tags">
                      <n-tag
                        v-for="marker in poc.success_evidence"
                        :key="marker"
                        size="small"
                        round
                        :bordered="false"
                        type="success"
                      >
                        {{ marker }}
                      </n-tag>
                    </div>

                    <n-collapse arrow-placement="right">
                      <n-collapse-item title="请求参数" name="params">
                        <n-code
                          :code="formatJson(poc.params || {})"
                          language="json"
                          word-wrap
                        />
                      </n-collapse-item>
                      <n-collapse-item title="请求摘录" name="request">
                        <n-code
                          :code="poc.request_excerpt || '暂无请求摘录'"
                          language="http"
                          word-wrap
                        />
                      </n-collapse-item>
                      <n-collapse-item title="响应摘录" name="response">
                        <n-code
                          :code="poc.response_excerpt || '暂无响应摘录'"
                          language="text"
                          word-wrap
                        />
                      </n-collapse-item>
                    </n-collapse>
                  </div>
                </n-card>
              </template>
              <n-empty v-else description="No PoC records yet" />
            </n-card>
          </div>

          <div class="stack-lg">
            <n-card title="任务摘要" size="small" embedded>
              <n-descriptions
                label-placement="left"
                :column="1"
                size="small"
                bordered
              >
                <n-descriptions-item label="目标范围">
                  {{ (task?.scope || []).join(', ') || 'n/a' }}
                </n-descriptions-item>
                <n-descriptions-item label="当前阶段">
                  {{ prettifyStage(task?.current_stage) }}
                </n-descriptions-item>
                <n-descriptions-item label="执行状态">
                  {{ prettifyStatus(task?.status) }}
                </n-descriptions-item>
                <n-descriptions-item label="最近摘要">
                  {{ task?.state?.last_summary || '暂无' }}
                </n-descriptions-item>
              </n-descriptions>
            </n-card>

            <n-card title="证据文件" size="small" embedded>
              <div v-if="artifacts.length" class="artifact-grid">
                <div v-for="artifact in artifacts" :key="artifact.id" class="artifact-row">
                  <div>
                    <strong>{{ artifact.title }}</strong>
                    <p class="subtle-text">{{ artifact.summary }}</p>
                  </div>
                  <div class="artifact-path">
                    <code>{{ fileNameFromPath(artifact.path) }}</code>
                    <span>{{ relativeArtifactPath(artifact.path) }}</span>
                  </div>
                </div>
              </div>
              <n-empty v-else description="暂无证据文件" />
            </n-card>
          </div>
        </div>
      </n-tab-pane>

      <n-tab-pane name="markdown" tab="原始报告">
        <n-card size="small" embedded>
          <n-code
            v-if="report?.markdown"
            :code="report.markdown"
            language="markdown"
            word-wrap
          />
          <n-empty v-else description="报告尚未生成" />
        </n-card>
      </n-tab-pane>
    </n-tabs>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import {
  NAlert,
  NCard,
  NCode,
  NCollapse,
  NCollapseItem,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NTabPane,
  NTabs,
  NTag,
} from 'naive-ui'
import { marked } from 'marked'
import DOMPurify from 'dompurify'

import {
  countConfirmedFindings,
  fileNameFromPath,
  prettifyStage,
  prettifyStatus,
  relativeArtifactPath,
  riskTagType,
} from '../utils/ui'

const props = defineProps({
  report: {
    type: Object,
    default: null,
  },
  task: {
    type: Object,
    default: null,
  },
  artifacts: {
    type: Array,
    default: () => [],
  },
  approvals: {
    type: Array,
    default: () => [],
  },
})

const findings = computed(() => props.task?.state?.findings || [])
const directPocs = computed(() => props.task?.state?.pocs || [])

// Synthesize PoCs from confirmed findings when state.pocs is empty
const pocs = computed(() => {
  if (directPocs.value.length) return directPocs.value
  const confirmed = findings.value.filter(
    f => String(f.confidence || '').toLowerCase() === 'confirmed'
  )
  if (!confirmed.length) return []

  // Derive PoC-like entries from confirmed findings and related actions
  const actions = props.task?.state?.actions || []
  return confirmed.map((f, idx) => {
    const relatedAction = actions.find(a =>
      a.summary && f.evidence_summary && (
        f.evidence_summary.includes(a.tool_name) ||
        a.tool_name === 'header_mutation' || a.tool_name === 'raw_http' ||
        a.tool_name === 'vuln_verify'
      )
    ) || actions[actions.length - 1]

    return {
      id: `synth-${idx}`,
      title: f.title || 'Confirmed finding',
      status: String(f.confidence || 'confirmed'),
      module: relatedAction?.tool_name || 'unknown',
      method: '—',
      path: '—',
      url: '',
      params: relatedAction?.params || {},
      request_excerpt: relatedAction?.summary || '',
      response_excerpt: '',
      success_evidence: [f.evidence_summary || ''],
      evidence_files: [],
      _synthesized: true,
    }
  })
})

const confirmedFindingCount = computed(() => countConfirmedFindings(findings.value))

const sanitizedHtml = computed(() => {
  const rawMarkdown = props.report?.markdown || ''
  if (!rawMarkdown) return ''
  const html = marked.parse(rawMarkdown)
  return DOMPurify.sanitize(html)
})

function formatJson(value) {
  return JSON.stringify(value, null, 2)
}
</script>
