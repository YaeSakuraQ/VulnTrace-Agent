import { createRouter, createWebHistory } from 'vue-router'

import TaskDetail from '../views/TaskDetail.vue'
import TaskList from '../views/TaskList.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'task-list', component: TaskList },
    { path: '/tasks/:taskId', name: 'task-detail', component: TaskDetail, props: true },
  ],
})

export default router
