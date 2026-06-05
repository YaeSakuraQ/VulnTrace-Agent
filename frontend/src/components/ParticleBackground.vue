<template>
  <canvas ref="canvasRef" class="particle-field" aria-hidden="true"></canvas>
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'

const canvasRef = ref(null)

let animationFrame = 0
let particles = []
let size = { width: 0, height: 0, dpr: 1 }
let pointer = { x: 0, y: 0, active: false }

function createParticles(count) {
  particles = Array.from({ length: count }, () => ({
    x: Math.random() * size.width,
    y: Math.random() * size.height,
    vx: (Math.random() - 0.5) * 0.24,
    vy: (Math.random() - 0.5) * 0.24,
    radius: 1 + Math.random() * 1.6,
  }))
}

function resize() {
  const canvas = canvasRef.value
  if (!canvas) {
    return
  }

  size = {
    width: window.innerWidth,
    height: window.innerHeight,
    dpr: Math.min(window.devicePixelRatio || 1, 2),
  }

  canvas.width = Math.floor(size.width * size.dpr)
  canvas.height = Math.floor(size.height * size.dpr)
  canvas.style.width = `${size.width}px`
  canvas.style.height = `${size.height}px`

  const count = Math.max(24, Math.min(58, Math.floor((size.width * size.height) / 26000)))
  createParticles(count)
}

function step() {
  const canvas = canvasRef.value
  if (!canvas) {
    return
  }

  const ctx = canvas.getContext('2d')
  if (!ctx) {
    return
  }

  ctx.setTransform(size.dpr, 0, 0, size.dpr, 0, 0)
  ctx.clearRect(0, 0, size.width, size.height)

  for (const particle of particles) {
    particle.x += particle.vx
    particle.y += particle.vy

    if (particle.x < 0 || particle.x > size.width) particle.vx *= -1
    if (particle.y < 0 || particle.y > size.height) particle.vy *= -1

    particle.x = Math.max(0, Math.min(size.width, particle.x))
    particle.y = Math.max(0, Math.min(size.height, particle.y))
  }

  for (let i = 0; i < particles.length; i += 1) {
    const a = particles[i]
    for (let j = i + 1; j < particles.length; j += 1) {
      const b = particles[j]
      const dx = a.x - b.x
      const dy = a.y - b.y
      const distance = Math.hypot(dx, dy)
      if (distance > 120) continue

      const alpha = (1 - distance / 120) * 0.18
      ctx.strokeStyle = `rgba(104, 208, 176, ${alpha})`
      ctx.lineWidth = 1
      ctx.beginPath()
      ctx.moveTo(a.x, a.y)
      ctx.lineTo(b.x, b.y)
      ctx.stroke()
    }
  }

  if (pointer.active) {
    for (const particle of particles) {
      const dx = pointer.x - particle.x
      const dy = pointer.y - particle.y
      const distance = Math.hypot(dx, dy)
      if (distance > 140) continue
      const force = (1 - distance / 140) * 0.018
      particle.vx -= dx * force * 0.0015
      particle.vy -= dy * force * 0.0015
    }
  }

  for (const particle of particles) {
    ctx.fillStyle = 'rgba(178, 234, 213, 0.78)'
    ctx.beginPath()
    ctx.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2)
    ctx.fill()
  }

  animationFrame = window.requestAnimationFrame(step)
}

function handlePointerMove(event) {
  pointer = {
    x: event.clientX,
    y: event.clientY,
    active: true,
  }
}

function handlePointerLeave() {
  pointer.active = false
}

onMounted(() => {
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  resize()
  window.addEventListener('resize', resize)
  window.addEventListener('pointermove', handlePointerMove)
  window.addEventListener('pointerleave', handlePointerLeave)

  if (!prefersReducedMotion) {
    animationFrame = window.requestAnimationFrame(step)
  } else {
    step()
  }
})

onBeforeUnmount(() => {
  window.cancelAnimationFrame(animationFrame)
  window.removeEventListener('resize', resize)
  window.removeEventListener('pointermove', handlePointerMove)
  window.removeEventListener('pointerleave', handlePointerLeave)
})
</script>

<style scoped>
.particle-field {
  position: fixed;
  inset: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 0;
  opacity: 0.72;
}
</style>
