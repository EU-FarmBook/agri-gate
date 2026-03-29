FROM golang:1.25-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg

RUN CGO_ENABLED=0 go build -o /out/agri-gate ./cmd/api

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=build /out/agri-gate /usr/local/bin/agri-gate

EXPOSE 8080

CMD ["/usr/local/bin/agri-gate"]
