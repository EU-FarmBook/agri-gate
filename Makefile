GO ?= go
BINARY ?= bin/agri-gate

.PHONY: run test build clean fmt lint docker-up docker-up-detached docker-down docker-logs

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
