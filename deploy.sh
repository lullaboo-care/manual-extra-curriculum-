#!/bin/bash

# Pull the latest changes
git pull origin main

# Build and start containers
docker-compose down
docker-compose build
docker-compose up -d

# Cleanup old images
docker image prune -f