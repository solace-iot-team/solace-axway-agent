######## Start a new stage from scratch #######
FROM alpine:latest  

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY ../sample/mysample.txt .

COPY /home/runner/work/solace-axway-agent/solace-axway-agent .
# Copy the Pre-built binary file from the previous stage

COPY ../bin/solace-axway-agent .

# Command to run the executable
CMD ["./solace-axway-agent"]
