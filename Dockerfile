# Builder Image
# ---------------------------------------------------
FROM golang:1.25-alpine AS go-builder

ARG VERSION=dev
ARG COMMIT=none

WORKDIR /usr/src/app

COPY . ./

RUN go mod download \
    && CGO_ENABLED=0 \
        GOOS=linux \
        go build \
          -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
          -trimpath -a -o main ./cmd/swan-ng


# Final Image
# ---------------------------------------------------
FROM dimaskiddo/alpine:base-glibc
MAINTAINER Dimas Restu Hidayanto <drh.dimasrestu@gmail.com>

ARG SERVICE_NAME="swan-ng"

ENV PATH $PATH:/usr/local/${SERVICE_NAME}

WORKDIR /usr/local/${SERVICE_NAME}

RUN apk --no-cache --update upgrade \
    && mkdir -p \
        ipsec.d \
        profile.d

COPY --from=go-builder /usr/src/app/main ./swan-ng
COPY --from=go-builder /usr/src/app/config.yaml.example ./config.yaml

EXPOSE 500/udp 4500/tcp 4500/udp 1701/udp

VOLUME ["/usr/local/swan-ng/ipsec.d", "/usr/local/swan-ng/profile.d"]
CMD ["swan-ng", "daemon", "--config", "./config.yaml"]
