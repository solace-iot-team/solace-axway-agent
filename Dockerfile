FROM golang:1.16.10-alpine3.14 AS build

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

RUN mkdir /opt/agent

RUN addgroup -S agent && adduser -S agent -G agent

WORKDIR /opt/agent

COPY --from=build /build/solace-axway-agent solace-axway-agent
COPY sample/agent-config.yml solace_axway_agent.yml

RUN chown -R agent /opt/agent

user agent

# Command to run the executable
CMD ["sh", "-c", "/opt/agent/solace-axway-agent"]

