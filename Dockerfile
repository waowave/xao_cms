FROM golang:latest AS builder
WORKDIR /usr/src/app
COPY go.mod go.sum main.go ./
RUN go mod download && go mod verify
RUN go build -v -o /usr/local/bin/xao_cms

FROM alpine:latest
RUN apk --no-cache add ca-certificates libc6-compat
WORKDIR /root/
EXPOSE 8080
ENV GIN_MODE=debug
CMD ["./xao_cms"]
COPY --from=builder /usr/local/bin/xao_cms .
