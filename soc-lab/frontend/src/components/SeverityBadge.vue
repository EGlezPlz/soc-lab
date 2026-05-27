<template>
  <span class="sev-badge" :class="severityClass">{{ label }}</span>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ level: { type: Number, required: true }, source: { type: String, default: 'wazuh' } })

const severityClass = computed(() => {
  // Wazuh: nivel 1–15; Suricata: severidad 1=alta, 2=media, 3=baja
  if (props.source === 'suricata') {
    return { 1: 'sev--critical', 2: 'sev--high', 3: 'sev--medium' }[props.level] ?? 'sev--low'
  }
  if (props.level >= 12) return 'sev--critical'
  if (props.level >= 8)  return 'sev--high'
  if (props.level >= 5)  return 'sev--medium'
  return 'sev--low'
})

const label = computed(() => {
  if (props.source === 'suricata') {
    return { 1: 'Alta', 2: 'Media', 3: 'Baja' }[props.level] ?? 'Info'
  }
  return `Nivel ${props.level}`
})
</script>

<style scoped>
.sev-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 600;
}
.sev--critical { background: #3b0000; color: #ff4444; border: 1px solid #ff444444; }
.sev--high     { background: #3a1a00; color: #ff8c00; border: 1px solid #ff8c0044; }
.sev--medium   { background: #2a2200; color: #ffd700; border: 1px solid #ffd70044; }
.sev--low      { background: #1a1a2e; color: #6c8ebf; border: 1px solid #6c8ebf44; }
</style>
