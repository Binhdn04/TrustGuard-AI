FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20-alpine AS build
WORKDIR /app
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_USE_MOCK_API=false
ARG NEXT_PUBLIC_DEMO_USER_TOKEN
ARG NEXT_PUBLIC_DEMO_ADMIN_TOKEN
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_PUBLIC_USE_MOCK_API=$NEXT_PUBLIC_USE_MOCK_API \
    NEXT_PUBLIC_DEMO_USER_TOKEN=$NEXT_PUBLIC_DEMO_USER_TOKEN \
    NEXT_PUBLIC_DEMO_ADMIN_TOKEN=$NEXT_PUBLIC_DEMO_ADMIN_TOKEN
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
EXPOSE 3000
CMD ["npm", "start"]
