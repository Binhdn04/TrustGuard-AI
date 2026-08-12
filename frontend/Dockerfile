# syntax=docker/dockerfile:1

ARG NODE_IMAGE=node:22.23.0-alpine3.23

FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,id=p068-frontend-npm,target=/root/.npm,sharing=locked \
    npm ci

FROM ${NODE_IMAGE} AS build
WORKDIR /app
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_USE_MOCK_API=false
ARG NEXT_PUBLIC_DEMO_USER_TOKEN
ARG NEXT_PUBLIC_DEMO_ADMIN_TOKEN
ARG NEXT_PUBLIC_OIDC_LOGIN_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_PUBLIC_USE_MOCK_API=$NEXT_PUBLIC_USE_MOCK_API \
    NEXT_PUBLIC_DEMO_USER_TOKEN=$NEXT_PUBLIC_DEMO_USER_TOKEN \
    NEXT_PUBLIC_DEMO_ADMIN_TOKEN=$NEXT_PUBLIC_DEMO_ADMIN_TOKEN \
    NEXT_PUBLIC_OIDC_LOGIN_URL=$NEXT_PUBLIC_OIDC_LOGIN_URL
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM ${NODE_IMAGE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    HOSTNAME=0.0.0.0 \
    PORT=3000
RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs
COPY --from=build --chown=nextjs:nodejs /app/public ./public
COPY --from=build --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=build --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
