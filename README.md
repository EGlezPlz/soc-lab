# SOC Lab

Plataforma personal de integración SOC con MISP, Wazuh y Suricata.

## Instalación rápida

```bash
git clone https://github.com/EGlezPlz/soc-lab.git
cd soc-lab
cp soc-lab/backend/.env.example soc-lab/backend/.env
# editar .env con las credenciales reales
./soc-lab/start.sh --build
```

Ver `soc-lab/README.md` para documentación completa.
