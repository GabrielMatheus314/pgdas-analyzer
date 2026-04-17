FROM node:20-alpine
WORKDIR /app

# Dependências nativas para canvas + Chromium (Puppeteer)
RUN apk add --no-cache \
    python3 make g++ \
    cairo-dev pango-dev jpeg-dev giflib-dev librsvg-dev pixman-dev \
    chromium nss freetype harfbuzz ca-certificates

# Usa o Chromium do sistema Alpine (não faz download separado)
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

COPY package*.json ./
RUN npm_config_nodedir=/usr/local npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
