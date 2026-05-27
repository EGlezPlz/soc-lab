<template>
  <div class="view">
    <div class="view__header">
      <div>
        <h1 class="view__title">Correlación MISP</h1>
        <p class="view__subtitle">Alertas de red cruzadas con inteligencia de amenazas</p>
      </div>
      <button class="btn" @click="refresh" :disabled="store.loading">
        {{ store.loading ? 'Analizando...' : 'Actualizar' }}
      </button>
    </div>

    <div class="stats-row">
      <div class="stat-card stat-card--alert">
        <span class="stat-card__value">{{ totalCorrelated }}</span>
        <span class="stat-card__label">Alertas correlacionadas</span>
        <span class="stat-card__sub">con threat intel de MISP</span>
      </div>
      <div class="stat-card">
        <span class="stat-card__value">{{ store.wazuhStats.correlated_count }}</span>
        <span class="stat-card__label">Wazuh → MISP</span>
        <span class="stat-card__sub">de {{ store.wazuhStats.total }} alertas</span>
      </div>
      <div class="stat-card">
        <span class="stat-card__value">{{ store.suricataStats.correlated_count }}</span>
        <span class="stat-card__label">Suricata → MISP</span>
        <span class="stat-card__sub">de {{ store.suricataStats.total }} alertas</span>
      </div>
      <div class="stat-card stat-card--clean">
        <span class="stat-card__value">{{ totalClean }}</span>
        <span class="stat-card__label">Sin correlación</span>
        <span class="stat-card__sub">tráfico aparentemente limpio</span>
      </div>
    </div>

    <section class="card lookup-card">
      <h2 class="section-title">Búsqueda manual de IP en MISP</h2>
      <div class="lookup-row">
        <input
          v-model="lookupIp"
          class="lookup-input"
          placeholder="Ej: 218.106.246.195"
          @keydown.enter="doLookup"
        />
        <button class="btn btn--accent" @click="doLookup" :disabled="lookupLoading">
          {{ lookupLoading ? 'Buscando...' : 'Buscar' }}
        </button>
      </div>
      <div v-if="lookupResult" class="lookup-result">
        <div v-if="lookupResult.found">
          <p class="lookup-found">✓ IP encontrada en MISP — {{ lookupResult.matches.length }} coincidencia(s)</p>
          <MispMatchCard v-for="m in lookupResult.matches" :key="m.event_id" :match="m" />
        </div>
        <p v-else class="lookup-notfound">✗ IP no encontrada en los IOCs de MISP</p>
      </div>
    </section>

    <div class="tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        class="tab"
        :class="{ 'tab--active': activeTab === tab.id }"
        @click="activeTab = tab.id"
      >
        {{ tab.label }}
        <span v-if="tab.count > 0" class="tab__badge">{{ tab.count }}</span>
      </button>
    </div>

    <!-- Tab Suricata -->
    <section v-if="activeTab === 'suricata'" class="card">
      <div class="filter-row">
        <label class="filter-toggle">
          <input type="checkbox" v-model="showOnlyCorrelated" />
          <span>Mostrar solo correlacionadas</span>
        </label>
        <span class="filter-info">{{ filteredSuricata.length }} alertas</span>
      </div>
      <div v-if="filteredSuricata.length === 0" class="empty">
        No hay alertas{{ showOnlyCorrelated ? ' correlacionadas' : '' }} de Suricata.
      </div>
      <div v-for="alert in pagedSuricata" :key="alert.flow_id" class="alert-row" :class="{ 'alert-row--correlated': alert.correlated }">
        <div class="alert-row__main">
          <ThreatBadge :correlated="alert.correlated" :tlp="alert.misp_matches[0]?.tlp" :severity="alert.severity" source="suricata" />
          <SeverityBadge :level="alert.severity" source="suricata" />
          <span class="alert-sig">{{ alert.signature }}</span>
          <span class="alert-flow">
            <span class="alert-ip">{{ alert.src_ip }}</span>
            <span class="alert-arrow">→</span>
            <span class="alert-ip">{{ alert.dest_ip }}</span>
            <span class="alert-proto">{{ alert.proto }}</span>
          </span>
          <span class="alert-ts">{{ alert.timestamp?.slice(0, 19).replace('T', ' ') }}</span>
        </div>
        <div v-if="alert.correlated" class="alert-row__matches">
          <MispMatchCard
            v-for="m in alert.misp_matches"
            :key="`${alert.flow_id}-${m.event_id}`"
            :match="m"
          />
        </div>
      </div>
      <div v-if="hasMoreSuricata" class="load-more">
        <button class="btn" @click="loadMoreSuricata">
          Cargar más — mostrando {{ showingSuricata }} de {{ totalSuricata }}
        </button>
      </div>
    </section>

    <!-- Tab Wazuh -->
    <section v-if="activeTab === 'wazuh'" class="card">
      <div class="filter-row">
        <label class="filter-toggle">
          <input type="checkbox" v-model="showOnlyCorrelated" />
          <span>Mostrar solo correlacionadas</span>
        </label>
        <span class="filter-info">{{ filteredWazuh.length }} alertas</span>
      </div>
      <div v-if="filteredWazuh.length === 0" class="empty">
        No hay alertas{{ showOnlyCorrelated ? ' correlacionadas' : '' }} de Wazuh.
      </div>
      <div v-for="alert in pagedWazuh" :key="alert.id" class="alert-row" :class="{ 'alert-row--correlated': alert.correlated }">
        <div class="alert-row__main">
          <ThreatBadge :correlated="alert.correlated" :tlp="alert.misp_matches[0]?.tlp" :severity="alert.level" source="wazuh" />
          <SeverityBadge :level="alert.level" source="wazuh" />
          <span class="alert-sig">{{ alert.rule_description }}</span>
          <span class="alert-agent">{{ alert.agent_name }}</span>
          <div v-if="alert.ips_found.length > 0" class="alert-ips">
            <span
              v-for="ip in alert.ips_found"
              :key="ip"
              class="alert-ip alert-ip--clickable"
              @click="quickLookup(ip)"
            >{{ ip }}</span>
          </div>
          <span class="alert-ts">{{ alert.timestamp?.slice(0, 19).replace('T', ' ') }}</span>
        </div>
        <div v-if="alert.correlated" class="alert-row__matches">
          <MispMatchCard
            v-for="m in alert.misp_matches"
            :key="`${alert.id}-${m.event_id}`"
            :match="m"
          />
        </div>
      </div>
      <div v-if="hasMoreWazuh" class="load-more">
        <button class="btn" @click="loadMoreWazuh">
          Cargar más — mostrando {{ showingWazuh }} de {{ totalWazuh }}
        </button>
      </div>
    </section>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useCorrelationStore } from '@/stores/correlation'
import { usePagination } from '@/composables/usePagination'
import ThreatBadge   from '@/components/ThreatBadge.vue'
import SeverityBadge from '@/components/SeverityBadge.vue'
import MispMatchCard from '@/components/MispMatchCard.vue'

const store = useCorrelationStore()

const activeTab          = ref('suricata')
const showOnlyCorrelated = ref(false)
const lookupIp           = ref('')
const lookupResult       = ref(null)
const lookupLoading      = ref(false)

const totalCorrelated = computed(() =>
  store.wazuhStats.correlated_count + store.suricataStats.correlated_count
)
const totalClean = computed(() =>
  store.wazuhStats.clean_count + store.suricataStats.clean_count
)
const filteredSuricata = computed(() =>
  showOnlyCorrelated.value
    ? store.suricataAlerts.filter(a => a.correlated)
    : store.suricataAlerts
)
const filteredWazuh = computed(() =>
  showOnlyCorrelated.value
    ? store.wazuhAlerts.filter(a => a.correlated)
    : store.wazuhAlerts
)
const tabs = computed(() => [
  { id: 'suricata', label: 'Suricata → MISP', count: store.suricataStats.correlated_count },
  { id: 'wazuh',    label: 'Wazuh → MISP',    count: store.wazuhStats.correlated_count },
])

const {
  items: pagedSuricata,
  hasMore: hasMoreSuricata,
  showing: showingSuricata,
  total: totalSuricata,
  loadMore: loadMoreSuricata,
  reset: resetSuricata,
} = usePagination(filteredSuricata, 25)

const {
  items: pagedWazuh,
  hasMore: hasMoreWazuh,
  showing: showingWazuh,
  total: totalWazuh,
  loadMore: loadMoreWazuh,
  reset: resetWazuh,
} = usePagination(filteredWazuh, 25)

watch(showOnlyCorrelated, () => {
  resetSuricata()
  resetWazuh()
})

async function refresh() {
  await Promise.all([store.fetchWazuh(200, true), store.fetchSuricata(200, true)])
}

async function doLookup() {
  if (!lookupIp.value.trim()) return
  lookupLoading.value = true
  lookupResult.value  = null
  try {
    lookupResult.value = await store.lookupIp(lookupIp.value.trim())
  } finally {
    lookupLoading.value = false
  }
}

function quickLookup(ip) {
  lookupIp.value = ip
  doLookup()
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

onMounted(refresh)
</script>

<style scoped>
.view           { padding: 2rem; max-width: 1300px; margin: 0 auto; }
.view__header   { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 1.5rem; }
.view__title    { font-size: 1.4rem; font-weight: 700; margin: 0; }
.view__subtitle { font-size: 0.8rem; color: var(--color-text-muted); margin: 0.2rem 0 0; }

.stats-row    { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.25rem; }
.stat-card    { background: var(--color-surface); border: 1px solid var(--color-border);
                border-radius: 10px; padding: 1.25rem; display: flex; flex-direction: column; gap: 2px; }
.stat-card--alert { border-color: #ff444433; }
.stat-card--clean { border-color: #4caf5033; }
.stat-card__value { font-size: 2.5rem; font-weight: 700; line-height: 1; }
.stat-card--alert .stat-card__value { color: #ff6b6b; }
.stat-card--clean .stat-card__value { color: #4caf50; }
.stat-card__label { font-size: 0.8rem; font-weight: 600; }
.stat-card__sub   { font-size: 0.7rem; color: var(--color-text-muted); }

.lookup-card  { margin-bottom: 1.25rem; }
.lookup-row   { display: flex; gap: 0.75rem; margin-top: 0.5rem; }
.lookup-input { flex: 1; padding: 0.5rem 0.75rem; background: var(--color-bg);
                border: 1px solid var(--color-border); border-radius: 6px;
                color: var(--color-text); font-family: monospace; font-size: 0.875rem; }
.lookup-input:focus { outline: none; border-color: var(--color-accent); }
.lookup-result  { margin-top: 1rem; }
.lookup-found   { color: #4caf50; font-size: 0.875rem; margin-bottom: 0.5rem; }
.lookup-notfound { color: var(--color-text-muted); font-size: 0.875rem; }

.tabs   { display: flex; gap: 4px; margin-bottom: 1rem; }
.tab    { padding: 0.5rem 1.25rem; border-radius: 6px 6px 0 0;
          border: 1px solid var(--color-border); border-bottom: none;
          background: var(--color-surface); color: var(--color-text-muted);
          cursor: pointer; font-size: 0.875rem; display: flex; align-items: center; gap: 0.5rem; }
.tab--active { color: var(--color-text); border-color: var(--color-accent); }
.tab__badge  { background: #ff4444; color: #fff; border-radius: 10px;
               padding: 0 6px; font-size: 0.65rem; font-weight: 700; }

.card         { background: var(--color-surface); border: 1px solid var(--color-border);
                border-radius: 0 10px 10px 10px; padding: 1.25rem; margin-bottom: 1.25rem; }
.section-title { font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
                 letter-spacing: 0.08em; color: var(--color-text-muted); margin: 0 0 0.75rem; }

.filter-row   { display: flex; align-items: center; justify-content: space-between;
                margin-bottom: 1rem; padding-bottom: 0.75rem; border-bottom: 1px solid var(--color-border); }
.filter-toggle { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; font-size: 0.875rem; }
.filter-info  { font-size: 0.75rem; color: var(--color-text-muted); }

.alert-row    { border-bottom: 1px solid var(--color-border); padding: 0.75rem 0; }
.alert-row:last-child { border-bottom: none; }
.alert-row--correlated { background: #ff44440a; border-radius: 6px; padding: 0.75rem; margin: 2px 0; }
.alert-row__main { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
.alert-sig    { flex: 1; font-size: 0.85rem; min-width: 200px; }
.alert-agent  { font-size: 0.75rem; color: var(--color-text-muted); font-family: monospace; }
.alert-flow   { display: flex; align-items: center; gap: 0.3rem; font-size: 0.75rem; }
.alert-ip     { font-family: monospace; font-size: 0.75rem; color: var(--color-text-muted); }
.alert-ip--clickable { cursor: pointer; color: var(--color-accent); text-decoration: underline dotted; }
.alert-ip--clickable:hover { color: #93c5fd; }
.alert-arrow  { color: var(--color-text-muted); font-size: 0.7rem; }
.alert-proto  { font-family: monospace; font-size: 0.65rem; color: var(--color-text-muted);
                background: var(--color-tag-bg); padding: 1px 5px; border-radius: 3px; }
.alert-ips    { display: flex; gap: 0.4rem; flex-wrap: wrap; }
.alert-ts     { font-family: monospace; font-size: 0.7rem; color: var(--color-text-muted);
                white-space: nowrap; margin-left: auto; }
.alert-row__matches { margin-top: 0.25rem; padding-left: 0.5rem; }

.empty { color: var(--color-text-muted); font-size: 0.875rem; padding: 1rem 0; text-align: center; }
.btn   { padding: 0.4rem 1rem; border-radius: 6px; border: 1px solid var(--color-border);
         background: transparent; color: var(--color-text); cursor: pointer; font-size: 0.875rem; }
.btn:hover { background: var(--color-surface-hover); }
.btn--accent { background: var(--color-accent); border-color: var(--color-accent); color: #fff; }
.btn--accent:hover { background: #2563eb; }
.load-more { display: flex; justify-content: center; padding: 1.25rem 0 0;
             border-top: 1px solid var(--color-border); margin-top: 0.5rem; }
</style>
