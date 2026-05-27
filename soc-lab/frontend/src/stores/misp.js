import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useMispStore = defineStore('misp', () => {
  const events  = ref([])
  const iocs    = ref([])
  const loading = ref(false)
  const error   = ref(null)
  const status  = ref(null)
  const lastFetch = ref(null)

  const TTL = 5 * 60 * 1000 // 5 minutos

  function isStale() {
    return !lastFetch.value || Date.now() - lastFetch.value > TTL
  }

  async function fetchStatus() {
    const res = await fetch('/api/misp/status')
    status.value = await res.json()
  }

  async function fetchEvents(limit = 20, force = false) {
    if (!force && !isStale() && events.value.length > 0) return
    loading.value = true
    error.value   = null
    try {
      const res = await fetch(`/api/misp/events?limit=${limit}`)
      const data = await res.json()
      events.value  = data.events
      lastFetch.value = Date.now()
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  async function fetchIocs(eventId = null, force = false) {
    if (!force && !isStale() && iocs.value.length > 0) return
    loading.value = true
    error.value   = null
    try {
      const params = eventId ? `?event_id=${eventId}` : ''
      const res  = await fetch(`/api/misp/iocs${params}`)
      const data = await res.json()
      iocs.value = data.iocs
    } catch (e) {
      error.value = e.message
    } finally {
      loading.value = false
    }
  }

  return { events, iocs, loading, error, status, lastFetch, fetchStatus, fetchEvents, fetchIocs }
}, {
  persist: {
    key: 'soc-lab-misp',
    paths: ['events', 'iocs', 'lastFetch'],
  }
})
