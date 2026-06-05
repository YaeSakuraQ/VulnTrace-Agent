<template>
  <div class="stack-xl">
    <section class="detail-hero">
      <div class="stack">
        <div class="hero-heading">
          <div>
            <p class="section-kicker">{{ prettifyStage(workspace.task?.current_stage) }}</p>
            <h2>{{ workspace.task?.name || '任务详情' }}</h2>
          </div>
          <n-tag
            round
            size="medium"
            :bordered="false"
            :type="statusTagType(workspace.task?.status)"
          >
            {{ prettifyStatus(workspace.task?.status) }}
          </n-tag>
        </div>
        <p class="hero-copy detail-copy">
          {{ workspace.task?.lab_description || '等待任务上下文。' }}
        </p>
        <div class="hero-meta">
          <span>范围 {{ (workspace.task?.scope || []).join(', ') || 'n/a' }}</span>
          <span>端口 {{ workspace.task?.ports || 'n/a' }}</span>
          <span>步骤 {{ workspace.task?.state?.step_count || 0 }} / {{ workspace.task?.state?.max_steps || 0 }}</span>
        </div>
      </div>

      <div class="hero-actions">
        <n-button type="primary" @click="handleRun">
          <template #icon>
            <Play :size="16" />
          </template>
          运行 / 继续
        </n-button>
        <n-button @click="handlePause">
          <template #icon>
            <Pause :size="16" />
          </template>
          暂停
        </n-button>
        <n-button type="error" ghost @click="handleStop">
          <template #icon>
            <Square :size="16" />
          </template>
          终止
        </n-button>
      </div>
    </section>

    <div class="stats-grid">
      <div class="metric-tile">
        <span class="metric-label">待审批</span>
        <strong>{{ pendingApprovals }}</strong>
      </div>
      <div class="metric-tile">
        <span class="metric-label">确认发现</span>
        <strong>{{ confirmedFindings }}</strong>
      </div>
      <div class="metric-tile">
        <span class="metric-label">证据文件</span>
        <strong>{{ workspace.artifacts.length }}</strong>
      </div>
      <div class="metric-tile">
        <span class="metric-label">事件数</span>
        <strong>{{ workspace.events.length }}</strong>
      </div>
    </div>

    <n-alert v-if="workspace.error" type="error" :show-icon="true">
      {{ workspace.error }}
    </n-alert>

    <n-tabs v-model:value="activeTab" type="line" animated>
      <n-tab-pane name="overview" tab="概览">
        <div class="detail-grid">
          <AgentConsole :task="workspace.task" />
          <PathGraph :graph="workspace.task?.state?.path_graph" />
        </div>
      </n-tab-pane>

      <n-tab-pane name="approvals" tab="审批">
        <ApprovalPanel
          :approvals="workspace.approvals"
          @approve="handleApprove"
          @reject="handleReject"
          @edit-approve="handleEditApprove"
        />
      </n-tab-pane>

      <n-tab-pane name="timeline" tab="活动">
        <EventTimeline :events="workspace.events" />
      </n-tab-pane>

      <n-tab-pane name="report" tab="报告">
        <ReportView
          :report="workspace.report"
          :task="workspace.task"
          :artifacts="workspace.artifacts"
          :approvals="workspace.approvals"
        />
      </n-tab-pane>
    </n-tabs>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { NAlert, NButton, NTabPane, NTabs, NTag } from 'naive-ui'
import { Pause, Play, Square } from '@lucide/vue'

import AgentConsole from '../components/AgentConsole.vue'
import ApprovalPanel from '../components/ApprovalPanel.vue'
import EventTimeline from '../components/EventTimeline.vue'
import PathGraph from '../components/PathGraph.vue'
import ReportView from '../components/ReportView.vue'
import { buildWsUrl } from '../api/client'
import {
  approveAction,
  editAndApproveAction,
  fetchApprovals,
  fetchArtifacts,
  fetchEvents,
  fetchReport,
  fetchTask,
  pauseTask,
  rejectAction,
  runTask,
  stopTask,
} from '../api/tasks'
import { createWorkspaceState } from '../store/useTaskStore'
import {
  countConfirmedFindings,
  prettifyStage,
  prettifyStatus,
  statusTagType,
} from '../utils/ui'

const route = useRoute()
const workspace = createWorkspaceState()
const activeTab = computed({
  get: () => workspace.activeTab || 'overview',
  set: (value) => {
    workspace.activeTab = value
  },
})
let socket = null

const pendingApprovals = computed(
  () => workspace.approvals.filter((item) => item.status === 'pending').length
)
const confirmedFindings = computed(() =>
  countConfirmedFindings(workspace.task?.state?.findings || [])
)

async function loadBundle() {
  workspace.loading = true
  workspace.error = ''
  const taskId = route.params.taskId
  try {
    workspace.task = await fetchTask(taskId)
    workspace.events = await fetchEvents(taskId)
    workspace.approvals = await fetchApprovals(taskId)
    workspace.artifacts = await fetchArtifacts(taskId)
    try {
      workspace.report = await fetchReport(taskId)
    } catch {
      workspace.report = null
    }
    if (workspace.activeTab === 'overview') {
      workspace.activeTab =
        workspace.task?.status === 'completed' && workspace.report?.markdown ? 'report' : 'overview'
    }
  } catch (requestError) {
    workspace.error = requestError.response?.data?.detail || requestError.message
  } finally {
    workspace.loading = false
  }
}

function connectSocket() {
  disconnectSocket()
  const taskId = route.params.taskId
  socket = new WebSocket(buildWsUrl(taskId))
  socket.onmessage = async (message) => {
    const payload = JSON.parse(message.data)
    if (payload.type === 'event') {
      workspace.events.push(payload.event)
      await refreshTaskFragments()
    }
    if (payload.type === 'task_snapshot') {
      workspace.task = payload.task
    }
  }
}

function disconnectSocket() {
  if (socket) {
    socket.close()
    socket = null
  }
}

async function refreshTaskFragments() {
  const taskId = route.params.taskId
  workspace.task = await fetchTask(taskId)
  workspace.approvals = await fetchApprovals(taskId)
  workspace.artifacts = await fetchArtifacts(taskId)
  try {
    workspace.report = await fetchReport(taskId)
  } catch {
    workspace.report = null
  }
}

async function handleRun() {
  await runTask(route.params.taskId)
  await loadBundle()
}

async function handlePause() {
  await pauseTask(route.params.taskId)
  await loadBundle()
}

async function handleStop() {
  await stopTask(route.params.taskId)
  await loadBundle()
}

async function handleApprove(approval) {
  await approveAction(approval.id, { note: 'Approved from UI.' })
  await loadBundle()
}

async function handleReject(approval) {
  await rejectAction(approval.id, { note: 'Rejected from UI.' })
  await loadBundle()
}

async function handleEditApprove(approval, editedParams) {
  await editAndApproveAction(approval.id, {
    note: 'Approved with parameter edits from UI.',
    edited_params: editedParams,
  })
  await loadBundle()
}

watch(
  () => route.params.taskId,
  async () => {
    workspace.activeTab = 'overview'
    await loadBundle()
    connectSocket()
  }
)

onMounted(async () => {
  await loadBundle()
  connectSocket()
})

onUnmounted(disconnectSocket)
</script>
