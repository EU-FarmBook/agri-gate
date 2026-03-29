# Deployment

This repository includes a Traefik-oriented deployment example in [deploy/online/docker-compose.online.yml](../deploy/online/docker-compose.online.yml) with runtime settings in [deploy/online/.env.online.example](../deploy/online/.env.online.example).

## Versioning

Do not leave `APP_VERSION=dev` in production. Set a real release-style value such as:

```bash
APP_VERSION=1.0.0
```

The container image reference can follow the same tag:

```bash
ghcr.io/eu-farmbook/agri-gate:1.0.0
```

## Image Flow

Build and push the image:

```bash
git push
make docker-build-image IMAGE=ghcr.io/eu-farmbook/agri-gate:1.0.0
make docker-push-image IMAGE=ghcr.io/eu-farmbook/agri-gate:1.0.0
```

## Server Flow

Prepare the deployment directory:

```bash
mkdir -p /opt/docker/agri_gate
cd /opt/docker/agri_gate
cp /path/to/repo/deploy/online/docker-compose.online.yml docker-compose.yml
cp /path/to/repo/deploy/online/.env.online.example .env.online
```

Edit `.env.online`:

- set `APP_VERSION` to the release you are deploying
- set a real `API_AUTH_TOKEN`
- set a real `POSTGRES_PASSWORD`
- keep `DATABASE_URL` aligned with that same password
- set `ENABLE_DEBUG_ROUTES=true` if you want the lightweight browser UI at `/debug/test`
- keep `ENABLE_DEBUG_ROUTES=false` if you want an API-only production deployment

Start the stack:

```bash
docker pull ghcr.io/eu-farmbook/agri-gate:1.0.0
docker compose pull
docker compose up -d
docker compose logs -f agri_gate
```

If you want to run a tag other than `latest`, update the `image:` line in `docker-compose.yml` on the server before `docker compose up -d`.

## Traefik

The provided compose file expects an external Docker network named `traefik-net` and routes traffic for:

```text
agrigate.nexavion.com
```

Adjust the Traefik host rule if you want a different domain or subdomain.

If you enable `/debug/test` in production, the page itself is public, but the scan actions still require the API token entered into the page.
