<template>
  <div class="workspace-grid">
    <TaskForm :templates="templates" :tasks="tasks" @submit="handleCreate" />

    <section class="stack-lg">
      <!-- Header -->
      <div class="section-header">
        <div>
          <p class="section-kicker">Workspace</p>
          <h2>Task Overview</h2>
        </div>
        <div class="section-actions">
          <n-input
            v-model:value="searchQuery"
            placeholder="Search tasks..."
            clearable
            size="small"
            style="width: 200px"
          >
            <template #prefix>
              <Search :size="14" />
            </template>
          </n-input>
          <n-button quaternary size="small" @click="loadTasks">
            <template #icon><RefreshCw :size="15" /></template>
          </n-button>
        </div>
      </div>

      <!-- Stats Grid -->
      <div class="stats-grid">
        <div class="metric-tile">
          <span class="metric-label">Total</span>
          <strong>{{ tasks.length }}</strong>
        </div>
        <div class="metric-tile metric-tile--running">
          <span class="metric-label">Running</span>
          <strong>{{ runningCount }}</strong>
        </div>
        <div class="metric-tile metric-tile--pending">
          <span class="metric-label">Awaiting Approval</span>
          <strong>{{ approvalCount }}</strong>
        </div>
        <div class="metric-tile metric-tile--done">
          <span class="metric-label">Completed</span>
          <strong>{{ completedCount }}</strong>
        </div>
        <div class="metric-tile metric-tile--failed">
          <span class="metric-label">Failed</span>
          <strong>{{ failedCount }}</strong>
        </div>
      </div>

      <n-alert v-if="error" type="error" :show-icon="true" closable @close="error = ''">
        {{ error }}
      </n-alert>

      <!-- Task List -->
      <div v-if="filteredTasks.length" class="task-list">
        <RouterLink
          v-for="task in filteredTasks"
          :key="task.id"
          :to="`/tasks/${task.id}`"
          class="task-item"
        >
          <div class="task-item__header">
            <div class="task-item__title-wrap">
              <h3 class="task-item__name">{{ task.name }}</h3>
              <p class="subtle-text task-item__objective">{{ task.objective || 'No objective set' }}</p>
            </div>
            <div class="task-item__badges">
              <n-tag round size="small" :bordered="false" :type="statusTagType(task.status)">
                {{ prettifyStatus(task.status) }}
              </n-tag>
            </div>
          </div>
          <div class="task-item__meta">
            <span class="meta-chip">{{ task.id.slice(0, 8) }}…</span>
            <span class="meta-chip">{{ prettifyStage(task.current_stage) }}</span>
            <span class="meta-chip">{{ truncateScope(task.scope) }}</span>
            <span class="meta-chip" v-if="task.ports">{{ task.ports }}</span>
          </div>
        </RouterLink>
      </div>
      <n-empty v-else description="No tasks yet. Create one to get started." />

    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { NAlert, NButton, NEmpty, NInput, NTag } from 'naive-ui'
import { RefreshCw, Search } from '@lucide/vue'

import TaskForm from '../components/TaskForm.vue'
import { createTask, fetchTaskTemplates, fetchTasks } from '../api/tasks'
import { prettifyStage, prettifyStatus, statusTagType } from '../utils/ui'

const router = useRouter()
const tasks = ref([])
const templates = ref([])
const error = ref('')
const searchQuery = ref('')

const runningCount = computed(() => tasks.value.filter(t => t.status === 'running').length)
const approvalCount = computed(() => tasks.value.filter(t => t.status === 'waiting_approval').length)
const completedCount = computed(() => tasks.value.filter(t => t.status === 'completed').length)
const failedCount = computed(() => tasks.value.filter(t => t.status === 'failed').length)

const filteredTasks = computed(() => {
  if (!searchQuery.value.trim()) return tasks.value
  const q = searchQuery.value.toLowerCase()
  return tasks.value.filter(t =>
    t.name.toLowerCase().includes(q) ||
    (t.objective || '').toLowerCase().includes(q) ||
    t.id.includes(q) ||
    (t.scope || []).some(s => s.includes(q))
  )
})

function truncateScope(scope) {
  const items = scope || []
  if (items.length <= 2) return items.join(', ')
  return items.slice(0, 2).join(', ') + ` +${items.length - 2}`
}

async function loadTasks() {
  error.value = ''
  try {
    tasks.value = await fetchTasks()
  } catch (e) {
    error.value = e.response?.data?.detail || e.message
  }
}

async function loadTemplates() {
  try {
    templates.value = await fetchTaskTemplates()
  } catch (e) {
    error.value = e.response?.data?.detail || e.message
  }
}

async function handleCreate(payload) {
  error.value = ''
  try {
    const task = await createTask(payload)
    await loadTasks()
    router.push(`/tasks/${task.id}`)
  } catch (e) {
    error.value = e.response?.data?.detail || e.message
  }
}

onMounted(async () => {
  await Promise.all([loadTasks(), loadTemplates()])
})
</script>

<style scoped>
.section-actions {
  display: flex; align-items: center; gap: 8px;
}
.task-item__title-wrap {
  flex: 1; min-width: 0;
}
.task-item__name {
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.task-item__objective {
  display: -webkit-box; -webkit-line-clamp: 1; -webkit-box-orient: vertical;
  overflow: hidden;
}
.task-item__badges {
  flex-shrink: 0; margin-left: 12px;
}
.meta-chip {
  display: inline-flex; align-items: center; padding: 3px 8px;
  background: rgba(255,255,255,0.04); border-radius: 4px;
  font-size: 12px; color: #8a9d93; white-space: nowrap;
  max-width: 160px; overflow: hidden; text-overflow: ellipsis;
}
.metric-tile--running { border-left: 3px solid #42d392; }
.metric-tile--pending { border-left: 3px solid #f0a020; }
.metric-tile--done { border-left: 3px solid #2080f0; }
.metric-tile--failed { border-left: 3px solid #e88080; }
</style>
