# Etapa 1 — Build del frontend con Vite
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Etapa 2 — Servidor Nginx con los ficheros estáticos
FROM nginx:alpine

# Configuración de Nginx (proxy + ficheros estáticos)
COPY nginx/nginx.conf /etc/nginx/conf.d/default.conf

# Ficheros estáticos generados por Vite
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
