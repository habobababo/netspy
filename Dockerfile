# --- Build: statisches Go-Binary (ohne CGO, SQLite ist in reinem Go eingebaut) ---
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY app/ ./app/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /netwatch .

# --- Laufzeit ---
FROM alpine:3.22
RUN apk add --no-cache iputils ca-certificates
COPY --from=build /netwatch /usr/local/bin/netwatch

ENV DB_PATH=/data/netwatch.db \
    TZ=Europe/Berlin

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s CMD wget -qO- http://127.0.0.1:${WEB_PORT:-8080}/health || exit 1

CMD ["netwatch"]
