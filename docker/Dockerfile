######## Start a new stage from scratch #######
FROM alpine:latest  

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY ../bin/solace-axway-agent .

# Command to run the executable
CMD ["./solace-axway-agent"]
