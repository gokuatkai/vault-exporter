FROM golang:1.12.5 as builder
RUN mkdir /build 
ADD . /build/
WORKDIR /build 
RUN go mod vendor && \
    go mod tidy 
RUN go build -o vault-exporter .
FROM buildpack-deps:stretch-scm
COPY --from=builder /build/vault-exporter /usr/bin/
ENTRYPOINT ["/usr/bin/vault-exporter"]