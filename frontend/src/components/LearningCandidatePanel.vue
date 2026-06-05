<template>
  <section class="stack-lg">
    <div class="section-header">
      <div>
        <p class="section-kicker">Learning</p>
        <h3>经验候选</h3>
      </div>
      <n-tag round size="small" :bordered="false" type="info">
        {{ pending.length }} 待审核
      </n-tag>
    </div>

    <n-card size="small" embedded>
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

            <n-input
              v-model:value="actionDrafts[candidate.id]"
              type="textarea"
              :autosize="{ minRows: 5, maxRows: 10 }"
              placeholder="建议动作 JSON"
            />

            <n-input
              v-model:value="recipeDrafts[candidate.id]"
              type="textarea"
              :autosize="{ minRows: 4, maxRows: 8 }"
              placeholder="验证草案 JSON"
            />

            <div class="actions-row actions-row--end">
              <n-button type="success" @click="approve(candidate)">批准并沉淀</n-button>
              <n-button type="error" ghost @click="reject(candidate)">拒绝</n-button>
            </div>
          </div>
        </n-card>
      </div>
      <n-empty v-else description="当前没有待审核经验" />
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
import { computed, reactive, watchEffect } from 'vue'
import { NButton, NCard, NEmpty, NInput, NTag } from 'naive-ui'

import { riskTagType } from '../utils/ui'

const props = defineProps({
  candidates: {
    type: Array,
    default: () => [],
  },
})

const emit = defineEmits(['approve', 'reject'])
const actionDrafts = reactive({})
const recipeDrafts = reactive({})

const pending = computed(() => props.candidates.filter((item) => item.status === 'pending'))
const history = computed(() => props.candidates.filter((item) => item.status !== 'pending'))

watchEffect(() => {
  pending.value.forEach((candidate) => {
    if (!actionDrafts[candidate.id]) {
      actionDrafts[candidate.id] = JSON.stringify(candidate.suggested_action || {}, null, 2)
    }
    if (!recipeDrafts[candidate.id]) {
      recipeDrafts[candidate.id] = JSON.stringify(candidate.verification_recipe || {}, null, 2)
    }
  })
})

function safeParse(text) {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

function approve(candidate) {
  const editedAction = safeParse(actionDrafts[candidate.id])
  const editedRecipe = safeParse(recipeDrafts[candidate.id])
  if (!editedAction || !editedRecipe) {
    window.alert('经验候选的 JSON 格式不正确。')
    return
  }
  emit('approve', candidate, editedAction, editedRecipe)
}

function reject(candidate) {
  emit('reject', candidate)
}
</script>
