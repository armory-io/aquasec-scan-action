FROM alpine:3.11

RUN apk add -U jq curl bash

COPY entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
