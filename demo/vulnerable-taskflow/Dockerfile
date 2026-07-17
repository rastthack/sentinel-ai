FROM node:22-bookworm-slim AS dependencies
WORKDIR /app
COPY prisma ./prisma
COPY prisma.config.ts ./prisma.config.ts
COPY package.json package-lock.json ./
RUN mkdir -p src
RUN npm ci

FROM dependencies AS build
COPY src ./src
COPY tsconfig.json tsconfig.build.json ./
RUN npm run prisma:generate
RUN npm run build

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
COPY prisma ./prisma
COPY prisma.config.ts ./prisma.config.ts
COPY package.json package-lock.json ./
RUN mkdir -p src
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod 0755 ./docker-entrypoint.sh
EXPOSE 4000
ENTRYPOINT ["./docker-entrypoint.sh"]
