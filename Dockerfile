FROM node:24-alpine

WORKDIR /app

# Create persistent data directory for SQLite and encryption key
RUN mkdir -p /app/data && chown -R node:node /app

COPY --chown=node:node package.json ./
COPY --chown=node:node scripts ./scripts
COPY --chown=node:node src ./src
COPY --chown=node:node public ./public

USER node

ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/app/data

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/api/health || exit 1

CMD ["node", "src/server.mjs"]
