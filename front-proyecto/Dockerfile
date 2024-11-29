#Construcción de la aplicación Angular
FROM node:18 AS build

#directorio de trabajo en el contenedor
WORKDIR /app

# Copiar los archivos necesarios para instalar las dependencias
COPY package*.json ./

# Instalar las dependencias de Node.js
RUN npm install

# Copiar todo el código fuente al contenedor
COPY . .

# Construir la aplicación Angular para producción
RUN npm run build --prod

#Servir la aplicación con Nginx
FROM nginx:alpine

# Copiar los archivos generados en la etapa de construcción al directorio de Nginx
# COPY --from=build /app/dist/tu-aplicacion-angular /usr/share/nginx/html

# Exponer el puerto 80 para servir la aplicación
EXPOSE 80

# Comando por defecto para iniciar Nginx
CMD ["nginx", "-g", "daemon off;"]
