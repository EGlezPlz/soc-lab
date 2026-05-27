import { createRouter, createWebHistory } from 'vue-router'
import DashboardView   from '@/views/DashboardView.vue'
import MispView        from '@/views/MispView.vue'
import WazuhView       from '@/views/WazuhView.vue'
import SuricataView    from '@/views/SuricataView.vue'
import CorrelationView from '@/views/CorrelationView.vue'

const routes = [
  { path: '/',            name: 'dashboard',   component: DashboardView },
  { path: '/misp',        name: 'misp',        component: MispView },
  { path: '/wazuh',       name: 'wazuh',       component: WazuhView },
  { path: '/suricata',    name: 'suricata',    component: SuricataView },
  { path: '/correlation', name: 'correlation', component: CorrelationView },
]

export default createRouter({
  history: createWebHistory(),
  routes,
})
