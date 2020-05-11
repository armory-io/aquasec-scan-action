FROM golang:1.14.2 AS builder

WORKDIR /go/src/github.com/armory-io/aquasec-scan-action/
COPY . .
RUN CGO_ENABLED=0 go build

FROM alpine:3.11

COPY --from=builder /go/src/github.com/armory-io/aquasec-scan-action/aquasec-scan-action .

ENTRYPOINT ["./aquasec-scan-action"]
