#!/bin/bash
docker-compose --env-file .env.local -f compose.yml up -d
