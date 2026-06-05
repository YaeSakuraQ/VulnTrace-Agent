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

    <n-card size="small" embedded>
      <div v-if="nodes.length" class="path-graph-container">
        <svg class="edge-svg" ref="svgRef" :viewBox="svgViewBox" preserveAspectRatio="xMidYMid meet">
          <line
            v-for="(edge, idx) in edgePositions"
            :key="`line-${idx}`"
            :x1="edge.x1"
            :y1="edge.y1"
            :x2="edge.x2"
            :y2="edge.y2"
            stroke="var(--n-border-color)"
            stroke-width="2"
            class="edge-line"
          />
        </svg>

        <div class="graph-columns">
          <div class="graph-column">
            <h4 class="graph-column__title graph-column__title--host">Host</h4>
            <div v-if="hostNodes.length" class="graph-column__nodes">
              <div
                v-for="node in hostNodes"
                :key="node.id"
                :ref="(el) => registerNodeRef(node.id, el)"
                :class="['graph-node', 'graph-node--host', { 'graph-node--selected': selectedNodeId === node.id }]"
                @click="selectNode(node)"
              >
                <span class="graph-node__label">{{ node.label }}</span>
                <span class="graph-node__type">{{ node.type }}</span>
              </div>
            </div>
            <n-empty v-else description="暂无主机" size="small" />
          </div>

          <div class="graph-column">
            <h4 class="graph-column__title graph-column__title--service">Service</h4>
            <div v-if="serviceNodes.length" class="graph-column__nodes">
              <div
                v-for="node in serviceNodes"
                :key="node.id"
                :ref="(el) => registerNodeRef(node.id, el)"
                :class="['graph-node', 'graph-node--service', { 'graph-node--selected': selectedNodeId === node.id }]"
                @click="selectNode(node)"
              >
                <span class="graph-node__label">{{ node.label }}</span>
                <span class="graph-node__type">{{ node.type }}</span>
              </div>
            </div>
            <n-empty v-else description="暂无服务" size="small" />
          </div>

          <div class="graph-column">
            <h4 class="graph-column__title graph-column__title--finding">Finding</h4>
            <div v-if="findingNodes.length" class="graph-column__nodes">
              <div
                v-for="node in findingNodes"
                :key="node.id"
                :ref="(el) => registerNodeRef(node.id, el)"
                :class="['graph-node', 'graph-node--finding', { 'graph-node--selected': selectedNodeId === node.id }]"
                @click="selectNode(node)"
              >
                <span class="graph-node__label">{{ node.label }}</span>
                <span class="graph-node__type">{{ node.type }}</span>
              </div>
            </div>
            <n-empty v-else description="暂无发现" size="small" />
          </div>
        </div>
      </div>
      <n-empty v-else description="无路径数据" size="small" />
    </n-card>

    <n-card v-if="selectedNode" size="small" embedded title="节点详情">
      <n-descriptions label-placement="left" :column="1" size="small" bordered>
        <n-descriptions-item label="ID">{{ selectedNode.id }}</n-descriptions-item>
        <n-descriptions-item label="Label">{{ selectedNode.label }}</n-descriptions-item>
        <n-descriptions-item label="Type">
          <n-tag size="small" round :bordered="false" :type="nodeTagType(selectedNode.type)">
            {{ selectedNode.type }}
          </n-tag>
        </n-descriptions-item>
        <n-descriptions-item v-if="selectedNode.metadata" label="Metadata">
          <n-code :code="formatJson(selectedNode.metadata)" language="json" word-wrap />
        </n-descriptions-item>
      </n-descriptions>
      <div v-if="relatedEdges.length" class="stack" style="margin-top: 12px">
        <h4>关联边</h4>
        <div v-for="edge in relatedEdges" :key="`${edge.source}-${edge.target}-${edge.label}`" class="edge-row">
          <span class="edge-row__source">{{ labelFor(edge.source) }}</span>
          <span class="edge-row__arrow">→</span>
          <span class="edge-row__target">{{ labelFor(edge.target) }}</span>
          <n-tag size="small" round :bordered="false">{{ edge.label }}</n-tag>
        </div>
      </div>
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
import { computed, nextTick, reactive, ref, watch } from 'vue'
import {
  NCard,
  NCode,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NTag,
} from 'naive-ui'

const props = defineProps({
  graph: {
    type: Object,
    default: () => ({ nodes: [], edges: [] }),
  },
})

const selectedNodeId = ref(null)
const nodeRefs = reactive({})
const svgRef = ref(null)

const nodes = computed(() => props.graph?.nodes || [])
const edges = computed(() => props.graph?.edges || [])
const nodeMap = computed(() =>
  Object.fromEntries(nodes.value.map((node) => [node.id, node.label]))
)

const hostNodes = computed(() => nodes.value.filter((node) => node.type === 'host'))
const serviceNodes = computed(() => nodes.value.filter((node) => node.type === 'service'))
const findingNodes = computed(() => nodes.value.filter((node) => node.type === 'finding'))

const selectedNode = computed(() =>
  nodes.value.find((n) => n.id === selectedNodeId.value) || null
)

const relatedEdges = computed(() => {
  if (!selectedNodeId.value) return []
  return edges.value.filter(
    (e) => e.source === selectedNodeId.value || e.target === selectedNodeId.value
  )
})

const svgViewBox = computed(() => {
  const cols = []
  if (hostNodes.value.length) cols.push(hostNodes.value)
  if (serviceNodes.value.length) cols.push(serviceNodes.value)
  if (findingNodes.value.length) cols.push(findingNodes.value)

  if (cols.length === 0) return '0 0 800 100'

  const colSpacing = 280
  const nodeHeight = 60
  const width = cols.length * colSpacing
  const maxNodes = Math.max(...cols.map((c) => c.length), 1)
  const height = maxNodes * nodeHeight + 40
  return `0 0 ${width} ${height}`
})

const edgePositions = computed(() => {
  const positions = []
  const typeOrder = { host: 0, service: 1, finding: 2 }

  edges.value.forEach((edge) => {
    const sourceNode = nodes.value.find((n) => n.id === edge.source)
    const targetNode = nodes.value.find((n) => n.id === edge.target)
    if (!sourceNode || !targetNode) return

    const sourceTypeIdx = typeOrder[sourceNode.type] ?? 0
    const targetTypeIdx = typeOrder[targetNode.type] ?? 2

    const sourceCol = sourceTypeIdx * 280 + 140
    const targetCol = targetTypeIdx * 280 + 140

    const sourceIdx = (nodes.value
      .filter((n) => n.type === sourceNode.type))
      .findIndex((n) => n.id === sourceNode.id)
    const targetIdx = (nodes.value
      .filter((n) => n.type === targetNode.type))
      .findIndex((n) => n.id === targetNode.id)

    const sourceY = sourceIdx >= 0 ? sourceIdx * 60 + 60 : 30
    const targetY = targetIdx >= 0 ? targetIdx * 60 + 60 : 30

    positions.push({
      x1: sourceCol,
      y1: sourceY,
      x2: targetCol,
      y2: targetY,
    })
  })

  return positions
})

function registerNodeRef(nodeId, el) {
  if (el) {
    nodeRefs[nodeId] = el
  }
}

function selectNode(node) {
  selectedNodeId.value = node.id
}

function labelFor(nodeId) {
  return nodeMap.value[nodeId] || nodeId
}

function nodeTagType(type) {
  const map = {
    host: 'info',
    service: 'success',
    finding: 'warning',
  }
  return map[type] || 'default'
}

function formatJson(value) {
  return JSON.stringify(value, null, 2)
}
</script>

<style scoped>
.path-graph-container {
  position: relative;
  overflow-x: auto;
  padding: 16px 0;
}

.edge-svg {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 1;
}

.edge-line {
  stroke-width: 2;
  opacity: 0.4;
  stroke-dasharray: 6 3;
}

.graph-columns {
  display: flex;
  gap: 24px;
  position: relative;
  z-index: 2;
}

.graph-column {
  flex: 1;
  min-width: 200px;
  background: var(--n-color-embedded);
  border-radius: 8px;
  padding: 12px;
}

.graph-column__title {
  margin: 0 0 8px 0;
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.graph-column__title--host {
  color: var(--primary-color, #2080f0);
}

.graph-column__title--service {
  color: var(--success-color, #18a058);
}

.graph-column__title--finding {
  color: var(--warning-color, #f0a020);
}

.graph-column__nodes {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.graph-node {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 10px 14px;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  border: 2px solid transparent;
  min-height: 48px;
}

.graph-node--host {
  background: rgba(32, 128, 240, 0.12);
  border-color: rgba(32, 128, 240, 0.35);
}

.graph-node--service {
  background: rgba(24, 160, 88, 0.12);
  border-color: rgba(24, 160, 88, 0.35);
}

.graph-node--finding {
  background: rgba(240, 160, 32, 0.12);
  border-color: rgba(240, 160, 32, 0.35);
}

.graph-node:hover {
  transform: translateY(-1px);
  filter: brightness(1.1);
}

.graph-node--selected {
  border-color: var(--primary-color, #2080f0);
  box-shadow: 0 0 12px rgba(32, 128, 240, 0.3);
}

.graph-node--selected.graph-node--host {
  border-color: var(--primary-color, #2080f0);
}

.graph-node--selected.graph-node--service {
  border-color: var(--success-color, #18a058);
}

.graph-node--selected.graph-node--finding {
  border-color: var(--warning-color, #f0a020);
}

.graph-node__label {
  font-size: 13px;
  font-weight: 600;
  color: var(--n-text-color);
  text-align: center;
  word-break: break-all;
}

.graph-node__type {
  font-size: 11px;
  opacity: 0.6;
  color: var(--n-text-color);
  margin-top: 2px;
}

.edge-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
}

.edge-row__source,
.edge-row__target {
  font-family: monospace;
  font-size: 13px;
  color: var(--n-text-color);
}

.edge-row__arrow {
  color: var(--n-text-color-3);
  font-size: 14px;
}

.stack {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
</style>
