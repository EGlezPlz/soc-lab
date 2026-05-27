import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useWazuhStore = defineStore('wazuh', () => {
  const agents    = ref([])
  const alerts    = ref([])
  const summary   = ref(null)
  const loading   = ref(false)
  const error     = ref(null)
  const lastFetch = ref(null)

  const TTL = 2 * 60 * 1000 // 2 minutos — alertas cambian más rápido

  function isStale() {
    return !lastFetch.value || Date.now() - lastFetch.value > TTL
  }

  async function fetchAgents(force = false) {
    if (!force && !isStale() && agents.value.length > 0) return
    loading.value = true
    error.value   = null
    try {
      const res  = await fetch('/api/wazuh/agents')
      const data = await res.json()
      agents.value  = data.agents
      summary.value = data.summary
      lastFetch.value = Date.now()
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchAlerts(params = {}, force = false) {
    if (!force && !isStale() && alerts.value.length > 0) return
    loading.value = true
    error.value   = null
    try {
      const qs  = new URLSearchParams(params).toString()
      const res = await fetch(`/api/wazuh/alerts?${qs}`)
      const data = await res.json()
      alerts.value = data.alerts
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  return { agents, alerts, summary, loading, error, lastFetch, fetchAgents, fetchAlerts }
}, {
  persist: {
    key: 'soc-lab-wazuh',
    paths: ['agents', 'alerts', 'summary', 'lastFetch'],
  }
})
