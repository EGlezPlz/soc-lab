<template>
  <div class="view">
    <div class="view__header">
      <h1 class="view__title">MISP — Inteligencia de amenazas</h1>
      <button class="btn" @click="mispStore.fetchEvents()" :disabled="mispStore.loading">
        {{ mispStore.loading ? 'Cargando...' : 'Actualizar' }}
      </button>
    </div>

    <p v-if="mispStore.error" class="error-msg">Error: {{ mispStore.error }}</p>

    <!-- Lista de eventos -->
    <section class="card">
      <h2 class="section-title">Eventos ({{ mispStore.events.length }})</h2>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>TLP</th><th>Info</th><th>Org</th><th>Fecha</th><th>Atributos</th><th>Tags</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="ev in mispStore.events" :key="ev.id" class="table-row" @click="selectedEvent = ev">
              <td><TlpBadge :tlp="ev.tlp" /></td>
              <td class="td-info">{{ ev.info }}</td>
              <td class="td-muted">{{ ev.org }}</td>
              <td class="td-muted">{{ ev.date }}</td>
              <td class="td-muted td-center">{{ ev.attribute_count }}</td>
              <td>
                <span v-for="tag in ev.tags" :key="tag" class="tag">{{ tag }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- IOCs del evento seleccionado -->
    <section v-if="selectedEvent" class="card">
      <h2 class="section-title">IOCs — {{ selectedEvent.info }}</h2>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr><th>TLP</th><th>Tipo</th><th>Valor</th><th>Comentario</th></tr>
          </thead>
          <tbody>
            <tr v-for="alert in pagedAlerts" :key="alert.id">
              <td><TlpBadge :tlp="ioc.tlp" /></td>
              <td class="td-muted td-mono">{{ ioc.type }}</td>
              <td class="td-mono">{{ ioc.value }}</td>
              <td class="td-muted">{{ ioc.comment }}</td>
            </tr>
            <tr v-if="eventIocs.length === 0">
              <td colspan="4" class="td-muted">Sin IOCs para este evento</td>
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
    <p v-else class="hint">Haz clic en un evento para ver sus IOCs</p>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useMispStore } from '@/stores/misp'
import TlpBadge from '@/components/TlpBadge.vue'
import { usePagination } from '@/composables/usePagination'

const mispStore    = useMispStore()
const selectedEvent = ref(null)

const { items: pagedEvents, hasMore, showing, total, loadMore } = usePagination(
  computed(() => mispStore.events)
)

const eventIocs = computed(() =>
  selectedEvent.value
    ? mispStore.iocs.filter(i => i.event_id === selectedEvent.value.id)
    : []
)

onMounted(async () => {
  await mispStore.fetchEvents()
  await mispStore.fetchIocs()
})
</script>

<style scoped>
.view           { padding: 2rem; max-width: 1200px; margin: 0 auto; }
.view__header   { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem; }
.view__title    { font-size: 1.4rem; font-weight: 700; margin: 0; }
.card           { background: var(--color-surface); border: 1px solid var(--color-border); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.25rem; }
.section-title  { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--color-text-muted); margin: 0 0 1rem; }
.table-wrap     { overflow-x: auto; }
.table          { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
.table th       { text-align: left; padding: 0.5rem 0.75rem; color: var(--color-text-muted); font-size: 0.75rem; font-weight: 600; border-bottom: 1px solid var(--color-border); }
.table td       { padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--color-border); vertical-align: middle; }
.table-row      { cursor: pointer; }
.table-row:hover td { background: var(--color-surface-hover); }
.td-info        { max-width: 280px; }
.td-muted       { color: var(--color-text-muted); }
.td-mono        { font-family: monospace; font-size: 0.8rem; }
.td-center      { text-align: center; }
.tag            { display: inline-block; margin: 0 3px 2px 0; padding: 1px 6px; background: var(--color-tag-bg); border-radius: 4px; font-size: 0.7rem; color: var(--color-text-muted); }
.hint           { color: var(--color-text-muted); font-size: 0.85rem; padding: 0.5rem 0; }
.error-msg      { color: #ff6b6b; font-size: 0.875rem; margin-bottom: 1rem; }
.btn            { padding: 0.4rem 1rem; border-radius: 6px; border: 1px solid var(--color-border); background: transparent; color: var(--color-text); cursor: pointer; font-size: 0.875rem; }
.btn:hover      { background: var(--color-surface-hover); }
.load-more { display: flex; justify-content: center; padding: 1.25rem 0 0; border-top: 1px solid var(--color-border); margin-top: 0.5rem; }
</style>
