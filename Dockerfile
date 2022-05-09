FROM golang:1.18.1 AS builder

COPY . .
RUN GOPATH= CGO_ENABLED=0 go build -o /bin/action

FROM alpine:3.15

COPY --from=builder /bin/action /aquasec-scan-action
ENTRYPOINT ["/aquasec-scan-action"]