FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci || npm install
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
# vite preview serves the built bundle and applies the same /api proxy the dev
# server uses, so the container needs no separate web server or CORS config.
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json /app/vite.config.ts ./
RUN addgroup -S app && adduser -S -G app app && chown -R app:app /app
USER app
EXPOSE 5173
CMD ["npx", "vite", "preview", "--host", "0.0.0.0", "--port", "5173"]
