import axios from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL || '/api'

export const apiClient = axios.create({
  baseURL,
  timeout: 30000,
})

export function buildWsUrl(taskId) {
  const configured = import.meta.env.VITE_WS_BASE_URL
  if (configured) {
    return `${configured}/tasks/${taskId}`
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}/ws/tasks/${taskId}`
}
