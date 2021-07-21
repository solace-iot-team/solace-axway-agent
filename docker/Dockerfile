FROM golang:1.13-alpine3.12 AS build

WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY main.go .
COPY pkg .

RUN go build -o /solace-axway-agent


######## Start a new stage from scratch #######
FROM alpine:latest  

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=build /solace-axway-agent /solace-axway-agent

# Command to run the executable
ENTRYPOINT ["/solace-axway-agent"]
