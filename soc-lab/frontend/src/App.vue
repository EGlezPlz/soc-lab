<template>
  <div class="app">
    <nav class="sidebar">
      <div class="sidebar__brand">
        <span class="sidebar__logo">⬡</span>
        <span class="sidebar__name">SOC Lab</span>
      </div>
      <ul class="sidebar__nav">
        <li v-for="item in navItems" :key="item.to">
          <RouterLink :to="item.to" class="nav-link" :class="{ 'nav-link--active': $route.path === item.to }">
            <span class="nav-link__icon">{{ item.icon }}</span>
            <span class="nav-link__label">{{ item.label }}</span>
          </RouterLink>
        </li>
      </ul>
      <div class="sidebar__footer">
        <span class="sidebar__version">v0.1.0 · Fase 1</span>
      </div>
    </nav>
    <main class="main">
      <RouterView />
    </main>
  </div>
</template>

<script setup>
const navItems = [
  { to: '/',            icon: '◈', label: 'Dashboard'   },
  { to: '/misp',        icon: '◎', label: 'MISP'        },
  { to: '/wazuh',       icon: '◉', label: 'Wazuh'       },
  { to: '/suricata',    icon: '◌', label: 'Suricata'    },
  { to: '/correlation', icon: '⬡', label: 'Correlación' },
]
</script>

<style>
/* Reset y variables globales */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --color-bg:           #0d0f14;
  --color-surface:      #131720;
  --color-surface-hover:#1a2030;
  --color-border:       #232a3a;
  --color-text:         #e2e8f0;
  --color-text-muted:   #64748b;
  --color-accent:       #3b82f6;
  --color-tag-bg:       #1e2535;
  --sidebar-width:      220px;
}

html, body { height: 100%; }

body {
  font-family: 'Inter', system-ui, sans-serif;
  background: var(--color-bg);
  color: var(--color-text);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

a { color: inherit; text-decoration: none; }
</style>

<style scoped>
.app {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

/* Sidebar */
.sidebar {
  width: var(--sidebar-width);
  flex-shrink: 0;
  background: var(--color-surface);
  border-right: 1px solid var(--color-border);
  display: flex;
  flex-direction: column;
  padding: 1.25rem 0;
}

.sidebar__brand {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 0 1.25rem 1.5rem;
  border-bottom: 1px solid var(--color-border);
}
.sidebar__logo {
  font-size: 1.4rem;
  color: var(--color-accent);
  line-height: 1;
}
.sidebar__name {
  font-size: 1rem;
  font-weight: 700;
  letter-spacing: 0.02em;
}

.sidebar__nav {
  list-style: none;
  padding: 1rem 0.75rem;
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.nav-link {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  padding: 0.55rem 0.75rem;
  border-radius: 7px;
  font-size: 0.9rem;
  color: var(--color-text-muted);
  transition: background 0.15s, color 0.15s;
}
.nav-link:hover {
  background: var(--color-surface-hover);
  color: var(--color-text);
}
.nav-link--active {
  background: #1e3a5f;
  color: #93c5fd;
}
.nav-link__icon { font-size: 1rem; line-height: 1; }
.nav-link__label { font-size: 0.875rem; }

.sidebar__footer {
  padding: 1rem 1.25rem 0;
  border-top: 1px solid var(--color-border);
}
.sidebar__version {
  font-size: 0.7rem;
  color: var(--color-text-muted);
  font-family: monospace;
}

/* Main content */
.main {
  flex: 1;
  overflow-y: auto;
  background: var(--color-bg);
}
</style>
