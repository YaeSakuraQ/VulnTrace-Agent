<template>
  <section class="stack-lg">
    <div class="section-header">
      <div>
        <p class="section-kicker">Relations</p>
        <h3>攻击路径视图</h3>
      </div>
      <n-tag round size="small" :bordered="false" type="info">
        {{ nodes.length }} 节点
      </n-tag>
    </div>

    <div class="path-summary-grid">
      <n-card size="small" embedded title="Host">
        <div class="path-badge-list">
          <div v-for="node in hostNodes" :key="node.id" class="path-badge">
            {{ node.label }}
          </div>
          <n-empty v-if="!hostNodes.length" description="暂无主机" size="small" />
        </div>
      </n-card>

      <n-card size="small" embedded title="Service">
        <div class="path-badge-list">
          <div v-for="node in serviceNodes" :key="node.id" class="path-badge">
            {{ node.label }}
          </div>
          <n-empty v-if="!serviceNodes.length" description="暂无服务" size="small" />
        </div>
      </n-card>
    </div>

    <n-card size="small" embedded title="Finding">
      <div v-if="findingNodes.length" class="finding-node-list">
        <div v-for="node in findingNodes" :key="node.id" class="finding-node-card">
          <span>{{ node.label }}</span>
        </div>
      </div>
      <n-empty v-else description="暂无发现" size="small" />
    </n-card>

    <n-card size="small" embedded title="关联关系">
      <div v-if="edges.length" class="stack">
        <div v-for="edge in edges" :key="`${edge.source}-${edge.target}-${edge.label}`" class="edge-row">
          <span class="edge-row__source">{{ labelFor(edge.source) }}</span>
          <span class="edge-row__arrow">→</span>
          <span class="edge-row__target">{{ labelFor(edge.target) }}</span>
          <n-tag size="small" round :bordered="false">{{ edge.label }}</n-tag>
        </div>
      </div>
      <n-empty v-else description="暂无路径连线" />
    </n-card>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import { NCard, NEmpty, NTag } from 'naive-ui'

const props = defineProps({
  graph: {
    type: Object,
    default: () => ({ nodes: [], edges: [] }),
  },
})

const nodes = computed(() => props.graph?.nodes || [])
const edges = computed(() => props.graph?.edges || [])
const nodeMap = computed(() =>
  Object.fromEntries(nodes.value.map((node) => [node.id, node.label]))
)
const hostNodes = computed(() => nodes.value.filter((node) => node.type === 'host'))
const serviceNodes = computed(() => nodes.value.filter((node) => node.type === 'service'))
const findingNodes = computed(() => nodes.value.filter((node) => node.type === 'finding'))

function labelFor(nodeId) {
  return nodeMap.value[nodeId] || nodeId
}
</script>
