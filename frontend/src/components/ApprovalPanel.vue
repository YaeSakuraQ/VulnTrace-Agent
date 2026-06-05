<template>
  <section class="stack-lg">
    <div class="section-header">
      <div>
        <p class="section-kicker">Approvals</p>
        <h3>高风险审批</h3>
      </div>
      <n-tag round size="small" :bordered="false" type="warning">
        {{ pending.length }} 待处理
      </n-tag>
    </div>

    <n-card size="small" embedded>
      <div v-if="pending.length" class="stack-lg">
        <n-card
          v-for="approval in pending"
          :key="approval.id"
          size="small"
          class="approval-card"
        >
          <template #header>
            <div class="card-header-inline">
              <div>
                <strong>{{ approval.tool_name }}</strong>
                <p class="subtle-text">{{ approval.target }}</p>
              </div>
              <n-tag
                round
                size="small"
                :bordered="false"
                :type="riskTagType(approval.risk_level)"
              >
                {{ approval.risk_level }}
              </n-tag>
            </div>
          </template>

          <div class="stack">
            <p>{{ approval.reason }}</p>

            <n-card v-if="hasParamsSchema(approval)" size="small" embedded title="参数编辑">
              <div class="dynamic-form-grid">
                <div
                  v-for="(schema, key) in approval.params_schema"
                  :key="key"
                  class="dynamic-form-field"
                >
                  <label class="dynamic-form-field__label">{{ key }}</label>
                  <n-input
                    v-if="schema.type === 'string' || !schema.type"
                    :value="getParamDraft(approval.id, key)"
                    @update:value="(v) => setParamDraft(approval.id, key, v)"
                    :placeholder="schema.description || key"
                  />
                  <n-input-number
                    v-else-if="schema.type === 'number' || schema.type === 'integer'"
                    :value="Number(getParamDraft(approval.id, key))"
                    @update:value="(v) => setParamDraft(approval.id, key, String(v))"
                  />
                  <n-switch
                    v-else-if="schema.type === 'boolean'"
                    :value="getParamDraft(approval.id, key) === 'true'"
                    @update:value="(v) => setParamDraft(approval.id, key, String(v))"
                  />
                  <n-input
                    v-else-if="schema.type === 'object' || schema.type === 'array'"
                    type="textarea"
                    :value="getParamDraft(approval.id, key)"
                    @update:value="(v) => setParamDraft(approval.id, key, v)"
                    :placeholder="schema.description || key"
                    :autosize="{ minRows: 2, maxRows: 5 }"
                  />
                </div>
              </div>
            </n-card>

            <n-card v-else size="small" embedded title="JSON 参数编辑">
              <n-input
                v-model:value="drafts[approval.id]"
                type="textarea"
                :autosize="{ minRows: 5, maxRows: 10 }"
                placeholder="审批参数 JSON"
              />
              <div class="json-actions">
                <n-button size="small" @click="formatJsonDraft(approval.id)">
                  格式化
                </n-button>
                <n-button size="small" @click="validateJsonDraft(approval.id)">
                  验证格式
                </n-button>
                <n-tag
                  v-if="jsonValidationStatus[approval.id] === 'valid'"
                  size="small"
                  round
                  :bordered="false"
                  type="success"
                >
                  格式正确
                </n-tag>
                <n-tag
                  v-else-if="jsonValidationStatus[approval.id] === 'invalid'"
                  size="small"
                  round
                  :bordered="false"
                  type="error"
                >
                  格式错误
                </n-tag>
              </div>
            </n-card>

            <div class="actions-row actions-row--end">
              <n-button type="success" @click="approve(approval)">批准</n-button>
              <n-button type="warning" ghost @click="editAndApprove(approval)">
                修改后批准
              </n-button>
              <n-button type="error" ghost @click="reject(approval)">拒绝</n-button>
            </div>
          </div>
        </n-card>
      </div>
      <n-empty v-else description="当前没有待审批动作" />
    </n-card>

    <n-card size="small" embedded title="近期审批记录">
      <div v-if="history.length" class="stack">
        <div v-for="approval in history" :key="approval.id" class="artifact-row">
          <div>
            <strong>{{ approval.tool_name }}</strong>
            <p class="subtle-text">{{ approval.reason }}</p>
          </div>
          <n-tag
            round
            size="small"
            :bordered="false"
            :type="riskTagType(approval.status)"
          >
            {{ approval.status }}
          </n-tag>
        </div>
      </div>
      <n-empty v-else description="暂无审批记录" />
    </n-card>
  </section>
</template>

<script setup>
import { computed, onUnmounted, reactive, watchEffect } from 'vue'
import {
  NButton,
  NCard,
  NEmpty,
  NInput,
  NInputNumber,
  NSwitch,
  NTag,
  useMessage,
} from 'naive-ui'

import { riskTagType } from '../utils/ui'

const props = defineProps({
  approvals: {
    type: Array,
    default: () => [],
  },
})

const emit = defineEmits(['approve', 'reject', 'edit-approve'])
const message = useMessage()
const drafts = reactive({})
const paramDrafts = reactive({})
const jsonValidationStatus = reactive({})

const pending = computed(() =>
  (props.approvals || []).filter((item) => item && item.status === 'pending')
)
const history = computed(() =>
  (props.approvals || []).filter((item) => item && item.status !== 'pending')
)

watchEffect(() => {
  pending.value.forEach((approval) => {
    if (!approval || !approval.id) return
    if (!drafts[approval.id]) {
      drafts[approval.id] = JSON.stringify(approval.params || {}, null, 2)
    }
    if (approval.params_schema) {
      Object.entries(approval.params_schema).forEach(([key]) => {
        const draftKey = `${approval.id}::${key}`
        if (paramDrafts[draftKey] === undefined) {
          const val = approval.params?.[key]
          paramDrafts[draftKey] = val !== undefined ? String(val) : ''
        }
      })
    }
  })
})

onUnmounted(() => {
  Object.keys(drafts).forEach((key) => {
    delete drafts[key]
  })
  Object.keys(paramDrafts).forEach((key) => {
    delete paramDrafts[key]
  })
  Object.keys(jsonValidationStatus).forEach((key) => {
    delete jsonValidationStatus[key]
  })
})

function hasParamsSchema(approval) {
  return (
    approval &&
    approval.params_schema &&
    typeof approval.params_schema === 'object' &&
    Object.keys(approval.params_schema).length > 0
  )
}

function getParamDraft(approvalId, key) {
  return paramDrafts[`${approvalId}::${key}`] ?? ''
}

function setParamDraft(approvalId, key, value) {
  paramDrafts[`${approvalId}::${key}`] = value
}

function formatJsonDraft(approvalId) {
  try {
    const parsed = JSON.parse(drafts[approvalId])
    drafts[approvalId] = JSON.stringify(parsed, null, 2)
    jsonValidationStatus[approvalId] = 'valid'
    message.success('格式化成功')
  } catch {
    jsonValidationStatus[approvalId] = 'invalid'
    message.error('JSON 格式错误，无法格式化')
  }
}

function validateJsonDraft(approvalId) {
  try {
    JSON.parse(drafts[approvalId])
    jsonValidationStatus[approvalId] = 'valid'
    message.success('JSON 格式正确')
  } catch (e) {
    jsonValidationStatus[approvalId] = 'invalid'
    message.error(`JSON 格式错误: ${e.message}`)
  }
}

function collectParams(approval) {
  if (hasParamsSchema(approval)) {
    const params = {}
    Object.keys(approval.params_schema).forEach((key) => {
      const draftKey = `${approval.id}::${key}`
      const raw = paramDrafts[draftKey]
      const schema = approval.params_schema[key]
      if (schema.type === 'number' || schema.type === 'integer') {
        params[key] = Number(raw)
      } else if (schema.type === 'boolean') {
        params[key] = raw === 'true'
      } else if (schema.type === 'object' || schema.type === 'array') {
        try {
          params[key] = JSON.parse(raw)
        } catch {
          params[key] = raw
        }
      } else {
        params[key] = raw
      }
    })
    return params
  }
  return null
}

function safeParse(jsonText) {
  try {
    return JSON.parse(jsonText)
  } catch {
    return null
  }
}

function approve(approval) {
  emit('approve', approval, approval.params)
}

function reject(approval) {
  emit('reject', approval)
}

function editAndApprove(approval) {
  let parsed
  if (hasParamsSchema(approval)) {
    parsed = collectParams(approval)
    if (!parsed) {
      message.error('无法收集参数。')
      return
    }
  } else {
    parsed = safeParse(drafts[approval.id])
    if (!parsed) {
      message.error('参数 JSON 格式不正确。')
      return
    }
  }
  emit('edit-approve', approval, parsed)
}
</script>

<style scoped>
.dynamic-form-grid {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.dynamic-form-field {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.dynamic-form-field__label {
  font-size: 13px;
  font-weight: 500;
  color: var(--n-text-color-2);
}

.json-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 8px;
}

.stack {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
</style>
