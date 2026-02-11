FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy source code
COPY . .

# Expose port
EXPOSE 3000

# Development server
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
