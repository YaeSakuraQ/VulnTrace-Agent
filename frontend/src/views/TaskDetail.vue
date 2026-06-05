<template>
  <div class="stack-xl">
    <!-- Hero -->
    <section class="detail-hero">
      <div class="stack">
        <div class="hero-heading">
          <div>
            <p class="section-kicker">{{ prettifyStage(workspace.task?.current_stage) }}</p>
            <h2>{{ workspace.task?.name || 'Task Detail' }}</h2>
          </div>
          <n-tag round size="medium" :bordered="false" :type="statusTagType(workspace.task?.status)">
            {{ prettifyStatus(workspace.task?.status) }}
          </n-tag>
        </div>
        <p class="hero-copy detail-copy">
          {{ workspace.task?.lab_description || 'Waiting for task context.' }}
        </p>
        <div class="hero-meta">
          <span>Scope {{ (workspace.task?.scope || []).join(', ') || 'n/a' }}</span>
          <span>Port {{ workspace.task?.ports || 'n/a' }}</span>
          <span>Step {{ workspace.task?.state?.step_count || 0 }} / {{ workspace.task?.state?.max_steps || 0 }}</span>
        </div>
      </div>
      <div class="hero-actions">
        <n-button type="primary" @click="handleRun"><template #icon><Play :size="16" /></template>Run</n-button>
        <n-button @click="handlePause"><template #icon><Pause :size="16" /></template>Pause</n-button>
        <n-button type="error" ghost @click="handleStop"><template #icon><Square :size="16" /></template>Stop</n-button>
      </div>
    </section>

    <!-- Stats -->
    <div class="stats-grid">
      <div class="metric-tile"><span class="metric-label">Pending</span><strong>{{ pendingApprovals }}</strong></div>
      <div class="metric-tile"><span class="metric-label">Confirmed</span><strong>{{ confirmedFindings }}</strong></div>
      <div class="metric-tile"><span class="metric-label">Artifacts</span><strong>{{ workspace.artifacts.length }}</strong></div>
      <div class="metric-tile"><span class="metric-label">Events</span><strong>{{ workspace.events.length }}</strong></div>
    </div>

    <n-alert v-if="workspace.error" type="error" :show-icon="true">{{ workspace.error }}</n-alert>

    <!-- Tabs -->
    <n-tabs v-model:value="activeTab" type="line" animated>
      <n-tab-pane name="overview" tab="Overview">
        <AgentConsole :task="workspace.task" />
        <PathGraph :graph="workspace.task?.state?.path_graph" style="margin-top: 20px" />
      </n-tab-pane>

      <n-tab-pane name="approvals" tab="Approvals">
        <ApprovalPanel
          :approvals="workspace.approvals"
          @approve="handleApprove" @reject="handleReject" @edit-approve="handleEditApprove"
        />
      </n-tab-pane>

      <n-tab-pane name="learning" tab="Learning">
        <LearningCandidatePanel
          :candidates="workspace.learningCandidates"
          @approve="handleApproveLearningCandidate" @reject="handleRejectLearningCandidate"
        />
      </n-tab-pane>

      <n-tab-pane name="timeline" tab="Activity">
        <EventTimeline :events="workspace.events" />
      </n-tab-pane>

      <n-tab-pane name="report" tab="Report">
        <ReportView :report="workspace.report" :task="workspace.task" :artifacts="workspace.artifacts" :approvals="workspace.approvals" />
      </n-tab-pane>

      <n-tab-pane name="usage" tab="Usage">
        <ApiBalancePanel />
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
import ApiBalancePanel from '../components/ApiBalancePanel.vue'
import ApprovalPanel from '../components/ApprovalPanel.vue'
import EventTimeline from '../components/EventTimeline.vue'
import LearningCandidatePanel from '../components/LearningCandidatePanel.vue'
import PathGraph from '../components/PathGraph.vue'
import ReportView from '../components/ReportView.vue'
import { buildWsUrl } from '../api/client'
import {
  approveAction, approveLearningCandidate, editAndApproveAction,
  fetchApprovals, fetchArtifacts, fetchEvents, fetchLearningCandidates,
  fetchReport, fetchTask, pauseTask, rejectAction, rejectLearningCandidate,
  runTask, stopTask,
} from '../api/tasks'
import { createWorkspaceState } from '../store/useTaskStore'
import { countConfirmedFindings, prettifyStage, prettifyStatus, statusTagType } from '../utils/ui'

const route = useRoute()
const workspace = createWorkspaceState()
const activeTab = computed({
  get: () => workspace.activeTab || 'overview',
  set: (v) => { workspace.activeTab = v },
})
let socket = null
let debounceTimer = null

const pendingApprovals = computed(() => workspace.approvals.filter(i => i.status === 'pending').length)
const confirmedFindings = computed(() => countConfirmedFindings(workspace.task?.state?.findings || []))

async function loadBundle() {
  workspace.loading = true
  workspace.error = ''
  const id = route.params.taskId
  try {
    const [task, events, approvals, candidates, artifacts] = await Promise.all([
      fetchTask(id), fetchEvents(id), fetchApprovals(id),
      fetchLearningCandidates(id), fetchArtifacts(id),
    ])
    workspace.task = task
    workspace.events = events
    workspace.approvals = approvals
    workspace.learningCandidates = candidates
    workspace.artifacts = artifacts
    try { workspace.report = await fetchReport(id) } catch { workspace.report = null }
  } catch (e) {
    workspace.error = e.response?.data?.detail || e.message
  } finally {
    workspace.loading = false
  }
}

function connectSocket() {
  disconnectSocket()
  socket = new WebSocket(buildWsUrl(route.params.taskId))
  socket.onmessage = async (msg) => {
    const payload = JSON.parse(msg.data)
    if (payload.type === 'event') workspace.events.push(payload.event)
    if (payload.type === 'task_snapshot') workspace.task = payload.task
    // Debounce refreshes to avoid flooding on rapid events
    clearTimeout(debounceTimer)
    debounceTimer = setTimeout(() => refreshTaskFragments(), 500)
  }
}

function disconnectSocket() {
  clearTimeout(debounceTimer)
  if (socket) { socket.close(); socket = null }
}

async function refreshTaskFragments() {
  const id = route.params.taskId
  try {
    const [task, approvals, candidates, artifacts] = await Promise.all([
      fetchTask(id), fetchApprovals(id), fetchLearningCandidates(id), fetchArtifacts(id),
    ])
    workspace.task = task
    workspace.approvals = approvals
    workspace.learningCandidates = candidates
    workspace.artifacts = artifacts
    try { workspace.report = await fetchReport(id) } catch { workspace.report = null }
  } catch { /* silent */ }
}

async function handleRun() { await runTask(route.params.taskId); await loadBundle() }
async function handlePause() { await pauseTask(route.params.taskId); await loadBundle() }
async function handleStop() { await stopTask(route.params.taskId); await loadBundle() }
async function handleApprove(a) { await approveAction(a.id, { note: 'Approved.' }); await loadBundle() }
async function handleReject(a) { await rejectAction(a.id, { note: 'Rejected.' }); await loadBundle() }
async function handleEditApprove(a, p) { await editAndApproveAction(a.id, { note: 'Approved with edits.', edited_params: p }); await loadBundle() }
async function handleApproveLearningCandidate(c, a, r) { await approveLearningCandidate(c.id, { note: 'Approved.', edited_suggested_action: a, edited_verification_recipe: r }); await loadBundle() }
async function handleRejectLearningCandidate(c) { await rejectLearningCandidate(c.id, { note: 'Rejected.' }); await loadBundle() }

watch(() => route.params.taskId, async () => { workspace.activeTab = 'overview'; await loadBundle(); connectSocket() })
onMounted(async () => { await loadBundle(); connectSocket() })
onUnmounted(disconnectSocket)
</script>
