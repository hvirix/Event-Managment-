# --- BUILD STAGE ---
FROM node:20-slim AS builder

# Install build dependencies for native modules (sqlite3, bcrypt)
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./

# Install all dependencies (including devDependencies if needed, or just production)
RUN npm install

# --- PRODUCTION STAGE ---
FROM node:20-slim AS runner

WORKDIR /app

# Copy built node_modules and package files
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./
COPY server.js ./
COPY public/ ./public

# Note: events.db is SQLite. If we want to persist data, we will use a Docker volume.
# We will create a directory for data and modify the application to store the DB there, 
# or just keep it in /app and mount a single file/directory.
# Let's keep events.db path as ./events.db in server.js, but we can mount a volume to /app/events.db.

EXPOSE 8080

ENV PORT=8080
ENV NODE_ENV=production

CMD ["npm", "start"]
