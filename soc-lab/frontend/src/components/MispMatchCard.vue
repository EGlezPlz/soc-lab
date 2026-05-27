<template>
  <div class="misp-match">
    <div class="misp-match__header">
      <TlpBadge :tlp="match.tlp" />
      <span class="misp-match__ip">{{ match.ip }}</span>
      <span class="misp-match__direction" :class="`misp-match__direction--${match.direction}`">
        {{ match.direction === 'src' ? '← origen' : '→ destino' }}
      </span>
    </div>
    <div class="misp-match__event">
      <span class="misp-match__label">Evento MISP</span>
      <a :href="match.misp_url" target="_blank" class="misp-match__link">
        #{{ match.event_id }} — {{ match.event_info }}
      </a>
    </div>
    <div class="misp-match__ioc">
      <span class="misp-match__label">IOC</span>
      <span class="misp-match__type">{{ match.ioc_type }}</span>
      <span class="misp-match__value">{{ match.ioc_value }}</span>
    </div>
    <div v-if="match.tags && match.tags.length > 0" class="misp-match__tags">
      <span v-for="tag in match.tags.slice(0, 5)" :key="tag" class="tag">{{ tag }}</span>
    </div>
  </div>
</template>

<script setup>
import TlpBadge from './TlpBadge.vue'
defineProps({ match: { type: Object, required: true } })
</script>

<style scoped>
.misp-match {
  background: var(--color-bg);
  border: 1px solid var(--color-border);
  border-left: 3px solid var(--color-accent);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
  margin-top: 0.5rem;
}
.misp-match__header { display: flex; align-items: center; gap: 0.5rem; }
.misp-match__ip     { font-family: monospace; font-size: 0.85rem; font-weight: 600; }
.misp-match__direction     { font-size: 0.7rem; color: var(--color-text-muted); }
.misp-match__direction--src { color: #ff9800; }
.misp-match__direction--dst { color: #2196f3; }
.misp-match__event  { display: flex; align-items: baseline; gap: 0.5rem; }
.misp-match__ioc    { display: flex; align-items: baseline; gap: 0.5rem; }
.misp-match__label  { font-size: 0.65rem; font-weight: 600; text-transform: uppercase;
                       letter-spacing: 0.06em; color: var(--color-text-muted); min-width: 70px; }
.misp-match__link   { font-size: 0.8rem; color: var(--color-accent); text-decoration: none; }
.misp-match__link:hover { text-decoration: underline; }
.misp-match__type   { font-family: monospace; font-size: 0.75rem;
                       background: var(--color-surface); padding: 1px 6px; border-radius: 3px;
                       color: var(--color-text-muted); }
.misp-match__value  { font-family: monospace; font-size: 0.8rem; }
.misp-match__tags   { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 2px; }
.tag { display: inline-block; padding: 1px 6px; background: var(--color-tag-bg);
       border-radius: 3px; font-size: 0.65rem; color: var(--color-text-muted); }
</style>
