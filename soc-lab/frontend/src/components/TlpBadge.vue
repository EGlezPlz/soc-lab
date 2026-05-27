<template>
  <span class="tlp-badge" :class="`tlp-badge--${tlp}`">
    TLP:{{ tlp.toUpperCase() }}
  </span>
</template>

<script setup>
defineProps({ tlp: { type: String, required: true } })
</script>

<style scoped>
.tlp-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  font-family: monospace;
}
.tlp-badge--red    { background: #500; color: #ff6b6b; border: 1px solid #ff6b6b44; }
.tlp-badge--amber  { background: #3a2800; color: #ffb347; border: 1px solid #ffb34744; }
.tlp-badge--green  { background: #002a00; color: #69db69; border: 1px solid #69db6944; }
.tlp-badge--clear,
.tlp-badge--white  { background: #1e1e2e; color: #cdd6f4; border: 1px solid #cdd6f444; }
</style>
