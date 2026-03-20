FROM node:20-alpine
WORKDIR /app

# Dependências nativas para compilar o pacote canvas (pdfjs-dist + renderização)
RUN apk add --no-cache python3 make g++ cairo-dev pango-dev jpeg-dev giflib-dev librsvg-dev pixman-dev

COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
