import { reactive } from 'vue'

export function createWorkspaceState() {
  return reactive({
    task: null,
    events: [],
    approvals: [],
    artifacts: [],
    report: null,
    activeTab: 'overview',
    loading: false,
    error: '',
  })
}
