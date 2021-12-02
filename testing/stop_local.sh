#!/bin/bash
docker-compose --env-file .env.local -f compose_local.yml down
