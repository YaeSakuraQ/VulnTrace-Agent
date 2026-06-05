<template>
  <section class="stack-lg">
    <div class="section-header">
      <div>
        <p class="section-kicker">Timeline</p>
        <h3>执行日志</h3>
      </div>
      <n-tag round size="small" :bordered="false" type="info">
        {{ events.length }} 条
      </n-tag>
    </div>

    <n-card size="small" embedded>
      <n-timeline v-if="events.length" size="large">
        <n-timeline-item
          v-for="event in orderedEvents"
          :key="event.id"
          :type="eventTimelineType(event.event_type)"
          :title="event.event_type"
          :content="event.message"
          :time="formatDateTime(event.created_at)"
        >
          <template #icon>
            <span class="timeline-badge">{{ event.stage || 'n/a' }}</span>
          </template>
        </n-timeline-item>
      </n-timeline>
      <n-empty v-else description="暂无日志事件" />
    </n-card>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import { NCard, NEmpty, NTag, NTimeline, NTimelineItem } from 'naive-ui'

import { formatDateTime } from '../utils/ui'

const props = defineProps({
  events: {
    type: Array,
    default: () => [],
  },
})

const orderedEvents = computed(() =>
  (props.events || []).slice().reverse()
)

function eventTimelineType(eventType) {
  const typeMap = {
    tool_completed: 'success',
    tool_failed: 'error',
    approval_requested: 'warning',
    task_paused: 'info',
    task_stopped: 'info',
  }
  return typeMap[eventType] || 'default'
}
</script>
