<template>
  <n-config-provider :theme="darkTheme" :theme-overrides="themeOverrides">
    <n-global-style />
    <n-message-provider>
      <div class="app-shell">
        <ParticleBackground />
        <header class="topbar">
          <div class="brand-block">
            <div class="brand-chip">
              <Shield class="brand-chip__icon" :size="16" />
              <span>Authorized Lab</span>
            </div>
            <div>
              <p class="brand-kicker">Local Security Workflow</p>
              <h1>VulnTrace Agent 工作台</h1>
            </div>
          </div>

          <nav class="topbar-nav">
            <RouterLink to="/" class="topbar-link">
              <LayoutDashboard :size="16" />
              <span>任务总览</span>
            </RouterLink>
          </nav>
        </header>

        <main class="content-shell">
          <RouterView />
        </main>
      </div>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup>
import { NConfigProvider, NGlobalStyle, NMessageProvider, darkTheme } from 'naive-ui'
import { LayoutDashboard, Shield } from '@lucide/vue'
import { RouterLink, RouterView } from 'vue-router'

import ParticleBackground from './components/ParticleBackground.vue'
import { themeOverrides } from './theme'
</script>
