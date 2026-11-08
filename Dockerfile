FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /centerauth ./cmd/server

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && adduser -D app && mkdir -p /data && chown app:app /data
COPY --from=builder /centerauth /usr/local/bin/centerauth
USER app
ENV HOST=0.0.0.0 PORT=3002 DATABASE_PATH=/data/centerauth.db
EXPOSE 3002
ENTRYPOINT ["centerauth"]
