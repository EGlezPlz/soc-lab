<template>
  <div class="view">
    <div class="view__header">
      <h1 class="view__title">Suricata — Alertas de red</h1>
      <div class="header-controls">
        <span class="ws-indicator" :class="suricataStore.wsConnected ? 'ws-indicator--live' : ''">
          {{ suricataStore.wsConnected ? '● LIVE' : '○ OFFLINE' }}
        </span>
        <button class="btn" @click="toggleLive">
          {{ suricataStore.wsConnected ? 'Desconectar' : 'Conectar live' }}
        </button>
      </div>
    </div>

    <!-- Stats -->
    <div class="summary-row" v-if="suricataStore.stats">
      <div class="summary-card summary-card--red">
        <span class="summary-value">{{ suricataStore.stats.by_severity.high }}</span>
        <span class="summary-label">Alta severidad</span>
      </div>
      <div class="summary-card summary-card--amber">
        <span class="summary-value">{{ suricataStore.stats.by_severity.medium }}</span>
        <span class="summary-label">Media severidad</span>
      </div>
      <div class="summary-card">
        <span class="summary-value">{{ suricataStore.stats.total_alerts }}</span>
        <span class="summary-label">Total alertas</span>
      </div>
      <div class="summary-card" v-if="suricataStore.wsConnected">
        <span class="summary-value live-count">{{ suricataStore.liveAlerts.length }}</span>
        <span class="summary-label">Eventos live</span>
      </div>
    </div>

    <!-- Feed en vivo -->
    <section v-if="suricataStore.liveAlerts.length > 0" class="card">
      <h2 class="section-title">Feed en tiempo real</h2>
      <div class="live-feed">
        <div
          v-for="alert in suricataStore.liveAlerts.slice(0, 15)"
          :key="alert.id"
          class="live-row"
          :class="`live-row--sev${alert.severity}`"
        >
          <SeverityBadge :level="alert.severity" source="suricata" />
          <span class="live-sig">{{ alert.signature }}</span>
          <span class="live-src">{{ alert.src_ip }}:{{ alert.src_port }}</span>
          <span class="live-arrow">→</span>
          <span class="live-dst">{{ alert.dest_ip }}:{{ alert.dest_port }}</span>
          <span class="live-proto td-mono">{{ alert.proto }}</span>
          <span class="live-ts">{{ alert.timestamp.slice(11, 19) }}</span>
        </div>
      </div>
    </section>

    <!-- Alertas históricas -->
    <section class="card">
      <h2 class="section-title">Alertas históricas</h2>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr><th>Sev.</th><th>Firma</th><th>Origen</th><th>Destino</th><th>Proto</th><th>Timestamp</th></tr>
          </thead>
          <tbody>
            <tr v-for="alert in pagedAlerts" :key="alert.id">
              <td><SeverityBadge :level="alert.severity" source="suricata" /></td>
              <td>{{ alert.signature }}</td>
              <td class="td-mono">{{ alert.src_ip }}:{{ alert.src_port }}</td>
              <td class="td-mono">{{ alert.dest_ip }}:{{ alert.dest_port }}</td>
              <td class="td-mono td-muted">{{ alert.proto }}</td>
              <td class="td-muted">{{ alert.timestamp }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="hasMore" class="load-more">
        <button class="btn" @click="loadMore">
          Cargar más — mostrando {{ showing }} de {{ total }}
        </button>
      </div>
    </section>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref, computed} from 'vue'
import { useSuricataStore } from '@/stores/suricata'
import SeverityBadge from '@/components/SeverityBadge.vue'
import { usePagination } from '@/composables/usePagination'

const suricataStore = useSuricataStore()

const { items: pagedAlerts, hasMore, showing, total, loadMore } = usePagination(
  computed(() => suricataStore.alerts)
)

function toggleLive() {
  suricataStore.wsConnected
    ? suricataStore.disconnectLive()
    : suricataStore.connectLive()
}

onMounted(async () => {
  await suricataStore.fetchAlerts()
  await suricataStore.fetchStats()
})

// Cierra el WebSocket si el usuario navega fuera
onUnmounted(() => suricataStore.disconnectLive())
</script>

<style scoped>
.view           { padding: 2rem; max-width: 1200px; margin: 0 auto; }
.view__header   { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem; }
.view__title    { font-size: 1.4rem; font-weight: 700; margin: 0; }
.header-controls { display: flex; align-items: center; gap: 1rem; }
.ws-indicator   { font-size: 0.75rem; font-family: monospace; font-weight: 600; color: var(--color-text-muted); }
.ws-indicator--live { color: #4caf50; animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }

.summary-row       { display: flex; gap: 1rem; margin-bottom: 1.25rem; flex-wrap: wrap; }
.summary-card      { flex: 1; min-width: 120px; background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 10px; padding: 1.25rem; }
.summary-card--red   { border-color: #f4433644; }
.summary-card--amber { border-color: #ff8c0044; }
.summary-value       { display: block; font-size: 2rem; font-weight: 700; }
.summary-label       { font-size: 0.75rem; color: var(--color-text-muted); }
.live-count { color: #4caf50; }

.card          { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.25rem; }
.section-title { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--color-text-muted); margin: 0 0 1rem; }

.live-feed     { display: flex; flex-direction: column; gap: 4px; }
.live-row      { display: flex; align-items: center; gap: 0.75rem; padding: 0.4rem 0.75rem; border-radius: 6px; font-size: 0.8rem; border-left: 3px solid transparent; animation: fadeIn 0.3s ease; }
.live-row--sev1 { border-left-color: #ff4444; background: #3b000011; }
.live-row--sev2 { border-left-color: #ff8c00; background: #3a1a0011; }
.live-row--sev3 { border-left-color: #ffd700; background: #2a220011; }
@keyframes fadeIn { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:translateY(0)} }
.live-sig   { flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.live-src, .live-dst { font-family: monospace; font-size: 0.75rem; color: var(--color-text-muted); white-space: nowrap; }
.live-arrow { color: var(--color-text-muted); }
.live-proto { font-size: 0.7rem; color: var(--color-text-muted); }
.live-ts    { font-family: monospace; font-size: 0.75rem; color: var(--color-text-muted); white-space: nowrap; }

.table-wrap { overflow-x: auto; }
.table      { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
.table th   { text-align: left; padding: 0.5rem 0.75rem; color: var(--color-text-muted); font-size: 0.75rem; font-weight: 600; border-bottom: 1px solid var(--color-border); }
.table td   { padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--color-border); vertical-align: middle; }
.td-muted   { color: var(--color-text-muted); }
.td-mono    { font-family: monospace; font-size: 0.8rem; }
.btn { padding: 0.4rem 1rem; border-radius: 6px; border: 1px solid var(--color-border); background: transparent; color: var(--color-text); cursor: pointer; font-size: 0.875rem; }
.btn:hover { background: var(--color-surface-hover); }
.load-more { display: flex; justify-content: center; padding: 1.25rem 0 0; border-top: 1px solid var(--color-border); margin-top: 0.5rem; }
</style>
