<template>
  <n-card class="tool-card" :bordered="false">
    <template #header>
      <div class="card-header-inline">
        <div>
          <p class="section-kicker">New Task</p>
          <h2>创建测试任务</h2>
        </div>
        <n-tag round size="small" :bordered="false" type="warning">
          本地授权
        </n-tag>
      </div>
    </template>

    <div class="stack-lg">
      <div v-if="templates.length" class="stack">
        <div class="section-header compact">
          <div>
            <h3>演示模板</h3>
            <p class="subtle-text">选一个模板，再细调范围、端口和目标。</p>
          </div>
        </div>

        <div class="template-grid">
          <button
            v-for="template in templates"
            :key="template.id"
            :class="['template-card', { active: selectedTemplateId === template.id }]"
            type="button"
            @click="applyTemplate(template)"
          >
            <div class="template-card__head">
              <strong>{{ template.title }}</strong>
              <n-tag size="small" round :bordered="false" type="info">
                {{ template.lab_type }}
              </n-tag>
            </div>
            <p>{{ template.summary }}</p>
            <span class="subtle-text">范围 {{ template.recommended_scope_examples.join(', ') }}</span>
          </button>
        </div>
      </div>

      <div v-if="selectedTemplate" class="template-summary-grid">
        <n-card size="small" embedded>
          <template #header>
            <span>现成任务</span>
          </template>
          <div v-if="existingTemplateTask" class="stack">
            <div class="template-task-head">
              <strong>{{ existingTemplateTask.name }}</strong>
              <n-tag size="small" round :bordered="false" type="success">
                {{ existingTemplateTask.status }}
              </n-tag>
            </div>
            <p class="subtle-text">{{ existingTemplateTask.objective }}</p>
            <div class="hero-meta">
              <span>{{ existingTemplateTask.scope.join(', ') }}</span>
              <span>{{ existingTemplateTask.ports }}</span>
              <span>{{ existingTemplateTask.current_stage }}</span>
            </div>
            <RouterLink :to="`/tasks/${existingTemplateTask.id}`" class="template-task-link">
              查看后端现成任务
            </RouterLink>
          </div>
          <p v-else class="subtle-text">当前后端还没有匹配这个模板的现成任务。</p>
        </n-card>

        <n-card size="small" embedded>
          <template #header>
            <span>范围 / 端口</span>
          </template>
          <div class="stack">
            <div class="inline-tags">
              <n-tag
                v-for="scopeExample in selectedTemplate.recommended_scope_examples"
                :key="scopeExample"
                size="small"
                round
                :bordered="false"
                @click="applyScopePreset(scopeExample)"
              >
                {{ scopeExample }}
              </n-tag>
            </div>
            <div class="inline-tags">
              <n-tag
                v-for="portPreset in selectedTemplate.recommended_port_presets"
                :key="portPreset"
                size="small"
                round
                :bordered="false"
                type="warning"
                @click="applyPortPreset(portPreset)"
              >
                {{ portPreset }}
              </n-tag>
            </div>
          </div>
        </n-card>

        <n-card size="small" embedded>
          <template #header>
            <span>风险重点</span>
          </template>
          <p class="subtle-text">{{ selectedTemplate.risk_focus }}</p>
        </n-card>

        <n-card size="small" embedded>
          <template #header>
            <span>演示顺序</span>
          </template>
          <ol class="ordered-list">
            <li v-for="step in selectedTemplate.demo_flow" :key="step">{{ step }}</li>
          </ol>
        </n-card>
      </div>

      <n-form label-placement="top" class="task-form-grid">
        <n-form-item label="任务名称">
          <n-input v-model:value="form.name" placeholder="例如：DVWA Web 检查" />
        </n-form-item>

        <n-form-item label="目标范围">
          <n-input v-model:value="form.scopeText" placeholder="例如：127.0.0.1, 192.168.56.10" />
        </n-form-item>

        <n-form-item label="端口范围">
          <n-input v-model:value="form.ports" placeholder="例如：80,443,8080" />
        </n-form-item>

        <n-form-item label="最大步骤数">
          <n-input-number v-model:value="form.maxSteps" :min="1" :max="20" />
        </n-form-item>

        <n-form-item class="task-form-grid__wide" label="授权说明">
          <n-input
            v-model:value="form.authorization"
            type="textarea"
            placeholder="填写靶场授权和边界。"
            :autosize="{ minRows: 3, maxRows: 5 }"
          />
        </n-form-item>

        <n-form-item class="task-form-grid__wide" label="靶场描述">
          <n-input
            v-model:value="form.labDescription"
            type="textarea"
            placeholder="描述目标服务、网络位置或实验背景。"
            :autosize="{ minRows: 3, maxRows: 5 }"
          />
        </n-form-item>

        <n-form-item class="task-form-grid__wide" label="测试目标">
          <n-input
            v-model:value="form.objective"
            type="textarea"
            placeholder="描述希望智能体完成的验证结果。"
            :autosize="{ minRows: 3, maxRows: 5 }"
          />
        </n-form-item>
      </n-form>

      <div class="actions-row">
        <n-button strong secondary @click="restoreTemplateDefaults" :disabled="!selectedTemplate">
          <template #icon>
            <RotateCcw :size="16" />
          </template>
          恢复模板
        </n-button>
        <div class="actions-row actions-row--end">
          <n-button type="primary" @click="submitForm(false)">
            <template #icon>
              <Save :size="16" />
            </template>
            创建任务
          </n-button>
          <n-button
            v-if="selectedTemplate"
            type="success"
            @click="submitForm(true)"
          >
            <template #icon>
              <Rocket :size="16" />
            </template>
            按模板创建并运行
          </n-button>
        </div>
      </div>
    </div>
  </n-card>
</template>

<script setup>
import { computed, reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'
import {
  NButton,
  NCard,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NTag,
} from 'naive-ui'
import { Rocket, RotateCcw, Save } from '@lucide/vue'

const props = defineProps({
  templates: {
    type: Array,
    default: () => [],
  },
  tasks: {
    type: Array,
    default: () => [],
  },
})

const emit = defineEmits(['submit'])
const selectedTemplateId = ref('')

const form = reactive({
  name: '本地靶场验证任务',
  scopeText: '127.0.0.1',
  authorization: '课程实验或本地授权靶场环境。',
  labDescription: '本地 Kali 环境下的授权靶场服务。',
  objective: '识别主机与服务，完成低风险验证并生成报告。',
  ports: '1-1024',
  maxSteps: 8,
})

const selectedTemplate = computed(
  () => props.templates.find((template) => template.id === selectedTemplateId.value) || null
)
const existingTemplateTask = computed(() => {
  if (!selectedTemplate.value) {
    return null
  }

  const preferences = {
    dvwa: ['DVWA FI PoC Report Chain', 'DVWA Real Verification Run', 'DVWA'],
    vulhub: ['Vulhub mini_httpd Live Demo', 'Vulhub'],
  }

  const orderedNames = preferences[selectedTemplate.value.id] || [selectedTemplate.value.title]
  for (const keyword of orderedNames) {
    const found = props.tasks.find((task) => task.name.includes(keyword))
    if (found) {
      return found
    }
  }

  return null
})

function applyTemplate(template) {
  selectedTemplateId.value = template.id
  applyTemplateDefaults(template)
}

function applyTemplateDefaults(template) {
  form.name = template.defaults.name
  form.scopeText = template.defaults.scope.join(', ')
  form.authorization = template.defaults.authorization
  form.labDescription = template.defaults.lab_description
  form.objective = template.defaults.objective
  form.ports = template.defaults.ports
  form.maxSteps = template.defaults.max_steps
}

function applyScopePreset(scopeExample) {
  form.scopeText = scopeExample
}

function applyPortPreset(portPreset) {
  form.ports = portPreset
}

function restoreTemplateDefaults() {
  if (!selectedTemplate.value) {
    return
  }

  applyTemplateDefaults(selectedTemplate.value)
}

function submitForm(autoRun = false) {
  emit('submit', {
    name: form.name,
    scope: form.scopeText
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean),
    authorization: form.authorization,
    lab_description: form.labDescription,
    objective: form.objective,
    ports: form.ports,
    max_steps: form.maxSteps,
    auto_run: autoRun,
  })
}
</script>
