import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Todas las llamadas a /api/* se redirigen al backend FastAPI
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      // El WebSocket de Suricata también pasa por el proxy
      '/api/suricata/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
})
