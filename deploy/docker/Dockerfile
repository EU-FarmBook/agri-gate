FROM golang:1.22-alpine

WORKDIR /app

COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg

RUN go build -o /usr/local/bin/agri-gate ./cmd/api

EXPOSE 8080

CMD ["/usr/local/bin/agri-gate"]
