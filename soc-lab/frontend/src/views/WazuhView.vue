<template>
  <div class="view">
    <div class="view__header">
      <h1 class="view__title">Wazuh — Alertas y agentes</h1>
      <button class="btn" @click="refresh" :disabled="wazuhStore.loading">
        {{ wazuhStore.loading ? 'Cargando...' : 'Actualizar' }}
      </button>
    </div>

    <!-- Resumen agentes -->
    <div class="summary-row" v-if="wazuhStore.summary">
      <div class="summary-card">
        <span class="summary-value">{{ wazuhStore.summary.total }}</span>
        <span class="summary-label">Total agentes</span>
      </div>
      <div class="summary-card summary-card--green">
        <span class="summary-value">{{ wazuhStore.summary.active }}</span>
        <span class="summary-label">Activos</span>
      </div>
      <div class="summary-card summary-card--red">
        <span class="summary-value">{{ wazuhStore.summary.disconnected }}</span>
        <span class="summary-label">Desconectados</span>
      </div>
    </div>

    <!-- Tabla agentes -->
    <section class="card">
      <h2 class="section-title">Agentes</h2>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr><th>ID</th><th>Nombre</th><th>IP</th><th>SO</th><th>Estado</th><th>Última conexión</th></tr>
          </thead>
          <tbody>
            <tr v-for="agent in wazuhStore.agents" :key="agent.id">
              <td class="td-mono td-muted">{{ agent.id }}</td>
              <td>{{ agent.name }}</td>
              <td class="td-mono">{{ agent.ip }}</td>
              <td class="td-muted">{{ agent.os }}</td>
              <td>
                <span class="status-badge" :class="agent.status === 'active' ? 'status-badge--up' : 'status-badge--down'">
                  {{ agent.status }}
                </span>
              </td>
              <td class="td-muted">{{ agent.last_keepalive }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- Tabla alertas -->
    <section class="card">
      <h2 class="section-title">Alertas recientes ({{ wazuhStore.alerts.length }})</h2>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr><th>Nivel</th><th>Descripción</th><th>Agente</th><th>Regla</th><th>Timestamp</th></tr>
          </thead>
          <tbody>
            <tr v-for="alert in pagedAlerts" :key="alert.id">
              <td><SeverityBadge :level="alert.level" source="wazuh" /></td>
              <td>{{ alert.rule_description }}</td>
              <td class="td-muted">{{ alert.agent_name }}</td>
              <td class="td-mono td-muted">{{ alert.rule_id }}</td>
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
import { onMounted, ref, computed } from 'vue'
import { useWazuhStore } from '@/stores/wazuh'
import SeverityBadge from '@/components/SeverityBadge.vue'
import { usePagination } from '@/composables/usePagination'

const wazuhStore = useWazuhStore()

const { items: pagedAlerts, hasMore, showing, total, loadMore } = usePagination(
  computed(() => wazuhStore.alerts)
)

async function refresh() {
  await wazuhStore.fetchAgents()
  await wazuhStore.fetchAlerts()
}

onMounted(refresh)
</script>

<style scoped>
.view           { padding: 2rem; max-width: 1200px; margin: 0 auto; }
.view__header   { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem; }
.view__title    { font-size: 1.4rem; font-weight: 700; margin: 0; }
.summary-row    { display: flex; gap: 1rem; margin-bottom: 1.25rem; }
.summary-card   { flex: 1; background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 10px; padding: 1.25rem; }
.summary-card--green { border-color: #4caf5044; }
.summary-card--red   { border-color: #f4433644; }
.summary-value  { display: block; font-size: 2rem; font-weight: 700; }
.summary-label  { font-size: 0.75rem; color: var(--color-text-muted); }
.card           { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.25rem; }
.section-title  { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--color-text-muted); margin: 0 0 1rem; }
.table-wrap     { overflow-x: auto; }
.table          { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
.table th       { text-align: left; padding: 0.5rem 0.75rem; color: var(--color-text-muted); font-size: 0.75rem; font-weight: 600; border-bottom: 1px solid var(--color-border); }
.table td       { padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--color-border); vertical-align: middle; }
.td-muted       { color: var(--color-text-muted); }
.td-mono        { font-family: monospace; font-size: 0.8rem; }
.status-badge   { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
.status-badge--up   { background: #002a00; color: #69db69; border: 1px solid #69db6944; }
.status-badge--down { background: #3b0000; color: #ff6b6b; border: 1px solid #ff6b6b44; }
.btn { padding: 0.4rem 1rem; border-radius: 6px; border: 1px solid var(--color-border); background: transparent; color: var(--color-text); cursor: pointer; font-size: 0.875rem; }
.btn:hover { background: var(--color-surface-hover); }
.load-more { display: flex; justify-content: center; padding: 1.25rem 0 0; border-top: 1px solid var(--color-border); margin-top: 0.5rem; }
</style>
