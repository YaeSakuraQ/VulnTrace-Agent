import { apiClient } from './client'

export async function fetchTasks() {
  const { data } = await apiClient.get('/tasks')
  return data
}

export async function fetchTaskTemplates() {
  const { data } = await apiClient.get('/tasks/templates')
  return data
}

export async function createTask(payload) {
  const { data } = await apiClient.post('/tasks', payload)
  return data
}

export async function fetchTask(taskId) {
  const { data } = await apiClient.get(`/tasks/${taskId}`)
  return data
}

export async function runTask(taskId) {
  const { data } = await apiClient.post(`/tasks/${taskId}/run`)
  return data
}

export async function pauseTask(taskId) {
  const { data } = await apiClient.post(`/tasks/${taskId}/pause`)
  return data
}

export async function stopTask(taskId) {
  const { data } = await apiClient.post(`/tasks/${taskId}/stop`)
  return data
}

export async function fetchEvents(taskId) {
  const { data } = await apiClient.get(`/tasks/${taskId}/events`)
  return data
}

export async function fetchArtifacts(taskId) {
  const { data } = await apiClient.get(`/tasks/${taskId}/artifacts`)
  return data
}

export async function fetchApprovals(taskId) {
  const { data } = await apiClient.get('/approvals', { params: { task_id: taskId } })
  return data
}

export async function approveAction(approvalId, payload) {
  const { data } = await apiClient.post(`/approvals/${approvalId}/approve`, payload)
  return data
}

export async function rejectAction(approvalId, payload) {
  const { data } = await apiClient.post(`/approvals/${approvalId}/reject`, payload)
  return data
}

export async function editAndApproveAction(approvalId, payload) {
  const { data } = await apiClient.post(`/approvals/${approvalId}/edit`, payload)
  return data
}

export async function fetchReport(taskId) {
  const { data } = await apiClient.get(`/reports/${taskId}`)
  return data
}
