import { ref, computed } from 'vue'

export function usePagination(source, pageSize = 25) {
  const currentSize = ref(pageSize)

  const items = computed(() => source.value.slice(0, currentSize.value))
  const hasMore = computed(() => source.value.length > currentSize.value)
  const total = computed(() => source.value.length)
  const showing = computed(() => Math.min(currentSize.value, source.value.length))

  function loadMore() {
    currentSize.value += pageSize
  }

  function reset() {
    currentSize.value = pageSize
  }

  return { items, hasMore, total, showing, loadMore, reset }
}
