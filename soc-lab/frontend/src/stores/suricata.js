import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useSuricataStore = defineStore('suricata', () => {
  const alerts      = ref([])
  const liveAlerts  = ref([])
  const stats       = ref(null)
  const loading     = ref(false)
  const error       = ref(null)
  const wsConnected = ref(false)
  const lastFetch   = ref(null)

  const TTL = 2 * 60 * 1000

  function isStale() {
    return !lastFetch.value || Date.now() - lastFetch.value > TTL
  }

  let ws = null

  async function fetchAlerts(severity = null, force = false) {
    if (!force && !isStale() && alerts.value.length > 0) return
    loading.value = true
    error.value   = null
    try {
      const params = severity ? `?severity=${severity}` : ''
      const res  = await fetch(`/api/suricata/alerts${params}`)
      const data = await res.json()
      alerts.value  = data.alerts
      lastFetch.value = Date.now()
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchStats(force = false) {
    if (!force && !isStale() && stats.value) return
    const res  = await fetch('/api/suricata/stats')
    stats.value = await res.json()
  }

  function connectLive() {
    if (ws) return
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    ws = new WebSocket(`${proto}://${window.location.host}/api/suricata/ws/live`)
    ws.onopen  = () => { wsConnected.value = true }
    ws.onclose = () => { wsConnected.value = false; ws = null }
    ws.onerror = () => { error.value = 'WebSocket desconectado' }
    ws.onmessage = (e) => {
      const event = JSON.parse(e.data)
      liveAlerts.value = [event, ...liveAlerts.value].slice(0, 100)
    }
  }

  function disconnectLive() {
    ws?.close()
    ws = null
  }

  return {
    alerts, liveAlerts, stats, loading, error, wsConnected, lastFetch,
    fetchAlerts, fetchStats, connectLive, disconnectLive,
  }
}, {
  persist: {
    key: 'soc-lab-suricata',
    paths: ['alerts', 'stats', 'lastFetch'],
    // liveAlerts y wsConnected NO se persisten — son efímeros
  }
})
