# Multi-stage build for Digital Forensics Toolkit
# Stage 1: Dependencies
FROM node:18-alpine AS deps

# Install security updates and required packages
RUN apk add --no-cache --update \
    && apk add --no-cache \
        ca-certificates \
        curl \
        dumb-init \
        su-exec \
        tini \
    && rm -rf /var/cache/apk/*

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Stage 2: Build (if needed for production builds)
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies including dev dependencies
RUN npm ci

# Copy source code
COPY . .

# Build application (if needed)
RUN npm run build

# Stage 3: Production
FROM node:18-alpine AS production

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs \
    && adduser -S forensics -u 1001

# Install security updates and required packages
RUN apk add --no-cache --update \
    && apk add --no-cache \
        ca-certificates \
        curl \
        dumb-init \
        su-exec \
        tini \
        sqlite \
    && rm -rf /var/cache/apk/*

# Create necessary directories
RUN mkdir -p /app/data /app/uploads /app/logs /app/temp \
    && chown -R forensics:nodejs /app

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy built application from builder stage
COPY --from=builder --chown=forensics:nodejs /app/dist ./dist

# Copy source code (for runtime)
COPY --chown=forensics:nodejs . .

# Create symlinks for data directories
RUN ln -sf /app/data /app/dist/data \
    && ln -sf /app/uploads /app/dist/uploads \
    && ln -sf /app/logs /app/dist/logs \
    && ln -sf /app/temp /app/dist/temp

# Set proper permissions
RUN chmod -R 755 /app \
    && chmod -R 770 /app/data /app/uploads /app/logs /app/temp

# Create healthcheck script
RUN echo '#!/bin/sh\ncurl -f http://localhost:3000/health || exit 1' > /app/healthcheck.sh \
    && chmod +x /app/healthcheck.sh

# Switch to non-root user
USER forensics

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /app/healthcheck.sh

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Use tini for zombie process reaping
CMD ["tini", "--", "node", "src/index.js"]

# Labels for metadata
LABEL maintainer="Digital Forensics Team <security@your-org.com>"
LABEL version="1.0.0"
LABEL description="Digital Forensics Toolkit - Secure evidence management and analysis"
LABEL org.opencontainers.image.title="Digital Forensics Toolkit"
LABEL org.opencontainers.image.description="A comprehensive digital forensics toolkit with security and compliance features"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="Your Organization"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/your-org/digital-forensics-toolkit"
