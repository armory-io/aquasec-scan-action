FROM golang:1.14.2 AS builder

COPY . .
RUN rm go.*
RUN CGO_ENABLED=0 go build -o /bin/action

FROM alpine:3.11

COPY --from=builder /bin/action /aquasec-scan-action
ENTRYPOINT ["/aquasec-scan-action"]