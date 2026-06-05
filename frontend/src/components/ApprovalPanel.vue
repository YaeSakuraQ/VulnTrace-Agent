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

            <n-input
              v-model:value="drafts[approval.id]"
              type="textarea"
              :autosize="{ minRows: 5, maxRows: 10 }"
              placeholder="审批参数"
            />

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
import { computed, reactive, watchEffect } from 'vue'
import { NButton, NCard, NEmpty, NInput, NTag } from 'naive-ui'

import { riskTagType } from '../utils/ui'

const props = defineProps({
  approvals: {
    type: Array,
    default: () => [],
  },
})

const emit = defineEmits(['approve', 'reject', 'edit-approve'])
const drafts = reactive({})

const pending = computed(() => props.approvals.filter((item) => item.status === 'pending'))
const history = computed(() => props.approvals.filter((item) => item.status !== 'pending'))

watchEffect(() => {
  pending.value.forEach((approval) => {
    if (!drafts[approval.id]) {
      drafts[approval.id] = JSON.stringify(approval.params, null, 2)
    }
  })
})

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
  const parsed = safeParse(drafts[approval.id])
  if (!parsed) {
    window.alert('参数 JSON 格式不正确。')
    return
  }
  emit('edit-approve', approval, parsed)
}
</script>
