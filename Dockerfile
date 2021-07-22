FROM golang:1.13-alpine3.12 AS build

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

RUN apk add --no-cache git make bash
WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN go build -o solace-axway-agent .


######## Start a new stage from scratch #######
FROM alpine:latest  

RUN apk --no-cache add ca-certificates

WORKDIR /root

COPY --from=build /build/solace-axway-agent solace-axway-agent

# Command to run the executable
CMD ["sh", "-c", "/root/solace-axway-agent  --pathConfig /var/agent/config"]

