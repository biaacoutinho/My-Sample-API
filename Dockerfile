<<<<<<< HEAD
FROM node:current-alpine
=======
FROM ubuntu:latest
>>>>>>> main
WORKDIR /app
COPY package*.json ./
ARG DEBIAN_FRONTEND=noninteractive
RUN npm install
COPY . .
EXPOSE 8080
CMD ["node", "index.js"]