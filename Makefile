GO ?= go
BINARY ?= bin/agri-gate
IMAGE ?= ghcr.io/eu-farmbook/agri-gate:latest

.PHONY: run test build clean fmt lint docker-up docker-up-detached docker-down docker-logs docker-build-image docker-push-image docker-publish-image

run:
	$(GO) run ./cmd/api

test:
	$(GO) test ./...

build:
	mkdir -p bin
	$(GO) build -o $(BINARY) ./cmd/api

clean:
	rm -rf bin

fmt:
	$(GO) fmt ./...

lint:
	$(GO) vet ./...

docker-up:
	docker compose up --build

docker-up-detached:
	docker compose up --build -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f api

docker-build-image:
	docker build -f deploy/docker/Dockerfile -t $(IMAGE) .

docker-push-image:
	docker push $(IMAGE)

docker-publish-image:
	docker build -f deploy/docker/Dockerfile -t $(IMAGE) .
	docker push $(IMAGE)
