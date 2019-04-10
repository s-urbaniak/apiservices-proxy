FROM golang:1.12-alpine3.9 as builder
WORKDIR /go/src/github.com/s-urbaniak/ssl-proxy
COPY . .
RUN CGO_ENABLED=0 go build -o ssl-proxy
RUN ls -l
RUN pwd

FROM scratch
COPY --from=builder /go/src/github.com/s-urbaniak/ssl-proxy/ssl-proxy /ssl-proxy
ENTRYPOINT ["/ssl-proxy"]
