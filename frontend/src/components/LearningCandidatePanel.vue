<template>
  <section class="stack-lg">
    <div class="section-header">
      <div>
        <p class="section-kicker">Learning</p>
        <h3>经验候选</h3>
      </div>
      <div class="section-header__tags">
        <n-tag v-if="loading" round size="small" :bordered="false" type="info">
          加载中...
        </n-tag>
        <n-tag round size="small" :bordered="false" type="info">
          {{ pending.length }} 待审核
        </n-tag>
      </div>
    </div>

    <n-card size="small" embedded>
      <n-spin :show="loading">
        <div v-if="pending.length" class="stack-lg">
          <n-card
            v-for="candidate in pending"
            :key="candidate.id"
            size="small"
            class="approval-card"
          >
            <template #header>
              <div class="card-header-inline">
                <div>
                  <strong>{{ candidate.title }}</strong>
                  <p class="subtle-text">{{ candidate.summary }}</p>
                </div>
                <n-tag round size="small" :bordered="false" type="warning">
                  {{ candidate.status }}
                </n-tag>
              </div>
            </template>

            <div class="stack">
              <p class="subtle-text">
                指纹：{{ candidate.signature?.service_product || 'unknown' }}
                {{ candidate.signature?.service_version || '' }}
              </p>
              <p class="subtle-text">
                推荐动作：`{{ candidate.suggested_action?.tool_name || 'unknown' }}`
              </p>
              <p class="subtle-text">
                验证草案：{{ candidate.verification_recipe?.summary || 'n/a' }}
              </p>

              <n-card size="small" embedded title="建议动作 JSON">
                <n-input
                  v-model:value="actionDrafts[candidate.id]"
                  type="textarea"
                  :autosize="{ minRows: 5, maxRows: 10 }"
                  placeholder="建议动作 JSON"
                />
                <div class="json-actions">
                  <n-button size="small" @click="formatDraft('action', candidate.id)">
                    格式化
                  </n-button>
                  <n-button size="small" @click="validateDraft('action', candidate.id)">
                    验证
                  </n-button>
                  <n-tag
                    v-if="actionValidation[candidate.id] === 'valid'"
                    size="small"
                    round
                    :bordered="false"
                    type="success"
                  >
                    格式正确
                  </n-tag>
                  <n-tag
                    v-else-if="actionValidation[candidate.id] === 'invalid'"
                    size="small"
                    round
                    :bordered="false"
                    type="error"
                  >
                    格式错误
                  </n-tag>
                </div>
              </n-card>

              <n-card size="small" embedded title="验证草案 JSON">
                <n-input
                  v-model:value="recipeDrafts[candidate.id]"
                  type="textarea"
                  :autosize="{ minRows: 4, maxRows: 8 }"
                  placeholder="验证草案 JSON"
                />
                <div class="json-actions">
                  <n-button size="small" @click="formatDraft('recipe', candidate.id)">
                    格式化
                  </n-button>
                  <n-button size="small" @click="validateDraft('recipe', candidate.id)">
                    验证
                  </n-button>
                  <n-tag
                    v-if="recipeValidation[candidate.id] === 'valid'"
                    size="small"
                    round
                    :bordered="false"
                    type="success"
                  >
                    格式正确
                  </n-tag>
                  <n-tag
                    v-else-if="recipeValidation[candidate.id] === 'invalid'"
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
                <n-button
                  type="success"
                  :loading="processingId === candidate.id"
                  @click="approve(candidate)"
                >
                  批准并沉淀
                </n-button>
                <n-button
                  type="error"
                  ghost
                  :loading="processingId === candidate.id"
                  @click="reject(candidate)"
                >
                  拒绝
                </n-button>
              </div>
            </div>
          </n-card>
        </div>
        <n-empty v-else v-if="!loading" description="当前没有待审核经验" />
      </n-spin>
    </n-card>

    <n-card size="small" embedded title="已审核经验">
      <div v-if="history.length" class="stack">
        <div v-for="candidate in history" :key="candidate.id" class="artifact-row">
          <div>
            <strong>{{ candidate.title }}</strong>
            <p class="subtle-text">{{ candidate.summary }}</p>
          </div>
          <n-tag round size="small" :bordered="false" :type="riskTagType(candidate.status)">
            {{ candidate.status }}
          </n-tag>
        </div>
      </div>
      <n-empty v-else description="暂无已审核经验" />
    </n-card>
  </section>
</template>

<script setup>
import { computed, onUnmounted, reactive, ref, watchEffect } from 'vue'
import {
  NButton,
  NCard,
  NEmpty,
  NInput,
  NSpin,
  NTag,
  useMessage,
} from 'naive-ui'

import { riskTagType } from '../utils/ui'

const props = defineProps({
  candidates: {
    type: Array,
    default: () => [],
  },
  loading: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['approve', 'reject'])
const message = useMessage()
const actionDrafts = reactive({})
const recipeDrafts = reactive({})
const actionValidation = reactive({})
const recipeValidation = reactive({})
const processingId = ref(null)

const pending = computed(() =>
  (props.candidates || []).filter((item) => item && item.status === 'pending')
)
const history = computed(() =>
  (props.candidates || []).filter((item) => item && item.status !== 'pending')
)

watchEffect(() => {
  pending.value.forEach((candidate) => {
    if (!candidate || !candidate.id) return
    if (!actionDrafts[candidate.id]) {
      actionDrafts[candidate.id] = JSON.stringify(candidate.suggested_action || {}, null, 2)
    }
    if (!recipeDrafts[candidate.id]) {
      recipeDrafts[candidate.id] = JSON.stringify(candidate.verification_recipe || {}, null, 2)
    }
  })
})

onUnmounted(() => {
  Object.keys(actionDrafts).forEach((key) => delete actionDrafts[key])
  Object.keys(recipeDrafts).forEach((key) => delete recipeDrafts[key])
  Object.keys(actionValidation).forEach((key) => delete actionValidation[key])
  Object.keys(recipeValidation).forEach((key) => delete recipeValidation[key])
})

function safeParse(text) {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

function formatDraft(type, candidateId) {
  const target = type === 'action' ? actionDrafts : recipeDrafts
  const validation = type === 'action' ? actionValidation : recipeValidation
  try {
    const parsed = JSON.parse(target[candidateId])
    target[candidateId] = JSON.stringify(parsed, null, 2)
    validation[candidateId] = 'valid'
    message.success('格式化成功')
  } catch {
    validation[candidateId] = 'invalid'
    message.error('JSON 格式错误，无法格式化')
  }
}

function validateDraft(type, candidateId) {
  const target = type === 'action' ? actionDrafts : recipeDrafts
  const validation = type === 'action' ? actionValidation : recipeValidation
  try {
    JSON.parse(target[candidateId])
    validation[candidateId] = 'valid'
    message.success('JSON 格式正确')
  } catch (e) {
    validation[candidateId] = 'invalid'
    message.error(`JSON 格式错误: ${e.message}`)
  }
}

function approve(candidate) {
  const editedAction = safeParse(actionDrafts[candidate.id])
  const editedRecipe = safeParse(recipeDrafts[candidate.id])
  if (!editedAction || !editedRecipe) {
    message.error('经验候选的 JSON 格式不正确。')
    return
  }
  processingId.value = candidate.id
  emit('approve', candidate, editedAction, editedRecipe)
}

function reject(candidate) {
  processingId.value = candidate.id
  emit('reject', candidate)
}
</script>

<style scoped>
.section-header__tags {
  display: flex;
  align-items: center;
  gap: 8px;
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
