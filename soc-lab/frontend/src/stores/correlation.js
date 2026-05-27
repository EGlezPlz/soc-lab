import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useCorrelationStore = defineStore('correlation', () => {
  const wazuhAlerts    = ref([])
  const suricataAlerts = ref([])
  const wazuhStats     = ref({ total: 0, correlated_count: 0, clean_count: 0 })
  const suricataStats  = ref({ total: 0, correlated_count: 0, clean_count: 0 })
  const loading        = ref(false)
  const error          = ref(null)
  const lastFetch      = ref(null)

  const TTL = 3 * 60 * 1000 // 3 minutos — es la operación más costosa

  function isStale() {
    return !lastFetch.value || Date.now() - lastFetch.value > TTL
  }

  async function fetchWazuh(limit = 200, force = false) {
    if (!force && !isStale() && wazuhAlerts.value.length > 0) return
    loading.value = true
    error.value   = null
    try {
      const res  = await fetch(`/api/correlation/alerts?limit=${limit}`)
      const data = await res.json()
      wazuhAlerts.value = data.alerts
      wazuhStats.value  = {
        total:            data.total,
        correlated_count: data.correlated_count,
        clean_count:      data.clean_count,
      }
      lastFetch.value = Date.now()
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchSuricata(limit = 200, force = false) {
    if (!force && !isStale() && suricataAlerts.value.length > 0) return
    loading.value = true
    error.value   = null
    try {
      const res  = await fetch(`/api/correlation/suricata?limit=${limit}`)
      const data = await res.json()
      suricataAlerts.value = data.alerts
      suricataStats.value  = {
        total:            data.total,
        correlated_count: data.correlated_count,
        clean_count:      data.clean_count,
      }
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function lookupIp(ip) {
    const res = await fetch(`/api/correlation/lookup/${ip}`)
    return await res.json()
  }

  return {
    wazuhAlerts, suricataAlerts,
    wazuhStats, suricataStats,
    loading, error, lastFetch,
    fetchWazuh, fetchSuricata, lookupIp,
  }
}, {
  persist: {
    key: 'soc-lab-correlation',
    paths: ['wazuhAlerts', 'suricataAlerts', 'wazuhStats', 'suricataStats', 'lastFetch'],
  }
})
