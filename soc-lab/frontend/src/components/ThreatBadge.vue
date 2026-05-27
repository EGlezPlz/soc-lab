<template>
  <span class="threat-badge" :class="`threat-badge--${level}`">
    {{ label }}
  </span>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  correlated: { type: Boolean, default: false },
  tlp:        { type: String, default: 'clear' },
  severity:   { type: Number, default: 3 },
  source:     { type: String, default: 'suricata' },
})

const level = computed(() => {
  if (!props.correlated) return 'clean'
  if (props.tlp === 'red')   return 'critical'
  if (props.tlp === 'amber') return 'high'
  if (props.source === 'suricata' && props.severity === 1) return 'critical'
  if (props.source === 'wazuh' && props.severity >= 12)   return 'critical'
  return 'medium'
})

const label = computed(() => {
  if (!props.correlated) return 'Limpia'
  if (level.value === 'critical') return '⚠ Crítica'
  if (level.value === 'high')     return '▲ Alta'
  return '● Correlacionada'
})
</script>

<style scoped>
.threat-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 10px;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  white-space: nowrap;
}
.threat-badge--clean    { background: #0f1a0f; color: #4caf50; border: 1px solid #4caf5033; }
.threat-badge--medium   { background: #1a1a00; color: #ffd700; border: 1px solid #ffd70055; }
.threat-badge--high     { background: #2a1500; color: #ff9800; border: 1px solid #ff980055; }
.threat-badge--critical { background: #2a0000; color: #ff4444; border: 1px solid #ff444466; animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.7} }
</style>
