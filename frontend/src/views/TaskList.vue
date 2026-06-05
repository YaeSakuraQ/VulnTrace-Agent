<template>
  <div class="workspace-grid">
    <TaskForm :templates="templates" :tasks="tasks" @submit="handleCreate" />

    <section class="stack-lg">
      <div class="section-header">
        <div>
          <p class="section-kicker">Workspace</p>
          <h2>任务总览</h2>
        </div>
        <n-button quaternary @click="loadTasks">
          <template #icon>
            <RefreshCw :size="16" />
          </template>
          刷新
        </n-button>
      </div>

      <div class="stats-grid">
        <div class="metric-tile">
          <span class="metric-label">任务总数</span>
          <strong>{{ tasks.length }}</strong>
        </div>
        <div class="metric-tile">
          <span class="metric-label">运行中</span>
          <strong>{{ runningCount }}</strong>
        </div>
        <div class="metric-tile">
          <span class="metric-label">待审批</span>
          <strong>{{ approvalCount }}</strong>
        </div>
        <div class="metric-tile">
          <span class="metric-label">已完成</span>
          <strong>{{ completedCount }}</strong>
        </div>
      </div>

      <n-alert v-if="error" type="error" :show-icon="true">
        {{ error }}
      </n-alert>

      <div v-if="tasks.length" class="task-list">
        <RouterLink
          v-for="task in tasks"
          :key="task.id"
          :to="`/tasks/${task.id}`"
          class="task-item"
        >
          <div class="task-item__header">
            <div>
              <h3>{{ task.name }}</h3>
              <p class="subtle-text">{{ task.objective }}</p>
            </div>
            <n-tag
              round
              size="small"
              :bordered="false"
              :type="statusTagType(task.status)"
            >
              {{ prettifyStatus(task.status) }}
            </n-tag>
          </div>

          <div class="task-item__meta">
            <span>{{ prettifyStage(task.current_stage) }}</span>
            <span>{{ task.scope.join(', ') }}</span>
            <span>{{ task.ports }}</span>
          </div>
        </RouterLink>
      </div>
      <n-empty v-else description="还没有任务" />
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import { NAlert, NButton, NEmpty, NTag } from 'naive-ui'
import { RefreshCw } from '@lucide/vue'

import TaskForm from '../components/TaskForm.vue'
import { createTask, fetchTaskTemplates, fetchTasks } from '../api/tasks'
import { prettifyStage, prettifyStatus, statusTagType } from '../utils/ui'

const router = useRouter()
const tasks = ref([])
const templates = ref([])
const error = ref('')

const runningCount = computed(() => tasks.value.filter((task) => task.status === 'running').length)
const approvalCount = computed(
  () => tasks.value.filter((task) => task.status === 'waiting_approval').length
)
const completedCount = computed(
  () => tasks.value.filter((task) => task.status === 'completed').length
)

async function loadTasks() {
  error.value = ''
  try {
    tasks.value = await fetchTasks()
  } catch (requestError) {
    error.value = requestError.response?.data?.detail || requestError.message
  }
}

async function loadTemplates() {
  try {
    templates.value = await fetchTaskTemplates()
  } catch (requestError) {
    error.value = requestError.response?.data?.detail || requestError.message
  }
}

async function handleCreate(payload) {
  error.value = ''
  try {
    const task = await createTask(payload)
    await loadTasks()
    router.push(`/tasks/${task.id}`)
  } catch (requestError) {
    error.value = requestError.response?.data?.detail || requestError.message
  }
}

onMounted(async () => {
  await loadTasks()
  await loadTemplates()
})
</script>
