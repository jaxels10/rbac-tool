# ---- Build stage ----
FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o rbac-tool .

# ---- Final stage ----
FROM scratch

# CA certs needed to reach the Kubernetes API server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=builder /app/rbac-tool /rbac-tool

EXPOSE 8080

ENTRYPOINT ["/rbac-tool"]
