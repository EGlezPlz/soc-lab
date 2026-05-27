<template>
  <div class="dashboard">
    <h1 class="dashboard__title">SOC Lab</h1>
    <p class="dashboard__subtitle">Estado de los servicios</p>

    <div class="dashboard__grid">
      <!-- Estado de servicios -->
      <section class="card">
        <h2 class="card__title">Servicios</h2>
        <div class="service-list">
          <div v-for="svc in services" :key="svc.name" class="service-row">
            <span class="service-dot" :class="
              svc.status === 'ok'       ? 'service-dot--up' :
              svc.status === 'checking' ? 'service-dot--checking' :
              'service-dot--down'
            " />
            <span class="service-name">{{ svc.name }}</span>
            <span class="service-status">{{ svc.label }}</span>
          </div>
        </div>
      </section>

      <!-- Resumen MISP -->
      <section class="card" @click="$router.push('/misp')" style="cursor:pointer">
        <h2 class="card__title">MISP</h2>
        <div class="stat-row">
          <div class="stat">
            <span class="stat__value">{{ mispStore.events.length }}</span>
            <span class="stat__label">Eventos</span>
          </div>
          <div class="stat">
            <span class="stat__value">{{ mispStore.iocs.length }}</span>
            <span class="stat__label">IOCs</span>
          </div>
        </div>
        <p class="card__hint">Ver módulo →</p>
      </section>

      <!-- Resumen Wazuh -->
      <section class="card" @click="$router.push('/wazuh')" style="cursor:pointer">
        <h2 class="card__title">Wazuh</h2>
        <div class="stat-row">
          <div class="stat">
            <span class="stat__value">{{ wazuhStore.summary?.active ?? '–' }}</span>
            <span class="stat__label">Agentes activos</span>
          </div>
          <div class="stat">
            <span class="stat__value">{{ wazuhStore.alerts.length }}</span>
            <span class="stat__label">Alertas</span>
          </div>
        </div>
        <p class="card__hint">Ver módulo →</p>
      </section>

      <!-- Resumen Suricata -->
      <section class="card" @click="$router.push('/suricata')" style="cursor:pointer">
        <h2 class="card__title">Suricata</h2>
        <div class="stat-row">
          <div class="stat">
            <span class="stat__value">{{ suricataStore.stats?.total_alerts ?? '–' }}</span>
            <span class="stat__label">Alertas</span>
          </div>

        </div>
        <p class="card__hint">Ver módulo →</p>
      </section>

      <!-- Resumen Correlación -->
      <section
        class="card card--correlation"
        :class="{ 'card--alert': totalCorrelated > 0 }"
        @click="$router.push('/correlation')"
        style="cursor:pointer"
      >
        <h2 class="card__title">Correlación MISP</h2>
        <div class="stat-row">
          <div class="stat">
            <span class="stat__value" :class="totalCorrelated > 0 ? 'stat__value--alert' : ''">
              {{ totalCorrelated }}
            </span>
            <span class="stat__label">Correlacionadas</span>
          </div>
          <div class="stat">
            <span class="stat__value stat__value--muted">{{ totalClean }}</span>
            <span class="stat__label">Sin correlación</span>
          </div>
        </div>

        <!-- Alertas críticas si las hay -->
        <div v-if="criticalMatches.length > 0" class="critical-list">
          <div v-for="m in criticalMatches.slice(0, 3)" :key="m.ip" class="critical-row">
            <span class="critical-dot" />
            <span class="critical-ip">{{ m.ip }}</span>
            <span class="critical-event">{{ m.misp_event?.slice(0, 40) }}…</span>
          </div>
        </div>
        <p v-else-if="totalCorrelated === 0" class="card__clean">✓ Sin amenazas correlacionadas</p>

        <p class="card__hint">Ver correlaciones →</p>
      </section>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref, computed } from 'vue'
import { useMispStore }        from '@/stores/misp'
import { useWazuhStore }       from '@/stores/wazuh'
import { useSuricataStore }    from '@/stores/suricata'
import { useCorrelationStore } from '@/stores/correlation'

const mispStore        = useMispStore()
const wazuhStore       = useWazuhStore()
const suricataStore    = useSuricataStore()
const correlationStore = useCorrelationStore()

const services = ref([
  { name: 'Backend API', status: 'checking', label: 'Comprobando...' },
  { name: 'MISP',        status: 'checking', label: 'Comprobando...' },
  { name: 'Wazuh',       status: 'checking', label: 'Comprobando...' },
  { name: 'Suricata',    status: 'checking', label: 'Comprobando...' },
])

const totalCorrelated = computed(() =>
  correlationStore.wazuhStats.correlated_count +
  correlationStore.suricataStats.correlated_count
)
const totalClean = computed(() =>
  correlationStore.wazuhStats.clean_count +
  correlationStore.suricataStats.clean_count
)

// Las IPs correlacionadas más críticas para mostrar en el dashboard
const criticalMatches = computed(() => {
  const matches = []
  const allAlerts = [
    ...correlationStore.wazuhAlerts,
    ...correlationStore.suricataAlerts,
  ]
  for (const alert of allAlerts) {
    if (!alert.correlated) continue
    for (const m of alert.misp_matches) {
      matches.push({ ip: m.ip, tlp: m.tlp, misp_event: m.event_info })
    }
  }
  // Ordenar: red primero, luego amber
  return matches.sort((a, b) => {
    const order = { red: 0, amber: 1, green: 2, clear: 3 }
    return (order[a.tlp] ?? 3) - (order[b.tlp] ?? 3)
  })
})

onMounted(async () => {
  await Promise.all([
    mispStore.fetchEvents(),
    mispStore.fetchIocs(),
    wazuhStore.fetchAgents(),
    wazuhStore.fetchAlerts(),
    suricataStore.fetchStats(),
    correlationStore.fetchWazuh(),
    correlationStore.fetchSuricata(),
  ])

  try {
    const res  = await fetch('/api/health')
    const data = await res.json()
    services.value = [
      { name: 'Backend API', status: data.status,           label: data.status === 'ok' ? 'Online' : 'Degradado' },
      { name: 'MISP',        status: data.services.misp,    label: data.labels.misp },
      { name: 'Wazuh',       status: data.services.wazuh,   label: data.labels.wazuh },
      { name: 'Suricata',    status: data.services.suricata, label: data.labels.suricata },
    ]
  } catch {
    services.value = [{ name: 'Backend API', status: 'error', label: 'No disponible' }]
  }
})
</script>

<style scoped>
.dashboard { padding: 2rem; max-width: 1200px; margin: 0 auto; }
.dashboard__title    { font-size: 1.75rem; font-weight: 700; margin: 0; color: var(--color-text); }
.dashboard__subtitle { color: var(--color-text-muted); margin: 0.25rem 0 2rem; }
.dashboard__grid     { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.25rem; }

.card {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: 10px;
  padding: 1.5rem;
  transition: border-color 0.2s;
}
.card:hover          { border-color: var(--color-accent); }
.card--alert         { border-color: #ff444455; }
.card--alert:hover   { border-color: #ff4444aa; }
.card__title  { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--color-text-muted); margin: 0 0 1rem; }
.card__hint   { font-size: 0.75rem; color: var(--color-accent); margin: 1rem 0 0; }
.card__clean  { font-size: 0.75rem; color: #4caf50; margin: 0.75rem 0 0; }

.service-list { display: flex; flex-direction: column; gap: 0.6rem; }
.service-row  { display: flex; align-items: center; gap: 0.6rem; font-size: 0.9rem; }
.service-dot  { width: 8px; height: 8px; border-radius: 50%; background: var(--color-border); flex-shrink: 0; }
.service-dot--up   { background: #4caf50; box-shadow: 0 0 6px #4caf5088; }
.service-dot--down { background: #f44336; }
.service-name   { flex: 1; }
.service-status { font-size: 0.75rem; color: var(--color-text-muted); font-family: monospace; }
.service-dot--checking { background: #64748b; animation: pulse 1.5s infinite; }

.stat-row { display: flex; gap: 2rem; }
.stat     { display: flex; flex-direction: column; }
.stat__value       { font-size: 2rem; font-weight: 700; color: var(--color-text); line-height: 1; }
.stat__value--alert { color: #ff6b6b; }
.stat__value--muted { color: var(--color-text-muted); font-size: 1.5rem; }
.stat__label { font-size: 0.75rem; color: var(--color-text-muted); margin-top: 0.25rem; }

.ws-dot       { font-size: 1rem; font-family: monospace; letter-spacing: 0.05em; }
.ws-dot--live { color: #4caf50; }

.critical-list { display: flex; flex-direction: column; gap: 0.4rem; margin-top: 0.75rem; }
.critical-row  { display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; }
.critical-dot  { width: 6px; height: 6px; border-radius: 50%; background: #ff4444; flex-shrink: 0;
                 animation: pulse 1.5s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
.critical-ip    { font-family: monospace; color: #ff6b6b; font-size: 0.75rem; flex-shrink: 0; }
.critical-event { color: var(--color-text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
