FROM node:20-alpine

# Install tzdata to manage timezones
RUN apk add --no-cache tzdata

# Set timezone to GMT+6 (Asia/Dhaka as example)
ENV TZ=Asia/Dhaka

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy rest of app
COPY . .

# Build TypeScript app
RUN npm run build

# Expose port (note: actual port must come from process.env.PORT)
EXPOSE 80

# Start app
CMD ["npm", "start"]
