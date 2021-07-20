.PHONY: all dep test lint build 

WORKSPACE ?= $$(pwd)

GO_PKG_LIST := $(shell go list ./... | grep -v /vendor/)

lint:
	@golint -set_exit_status ${GO_PKG_LIST}

dep:
	@echo "Resolving go package dependencies"
	@go mod tidy
	@go mod vendor
	@echo "Package dependencies completed"

update-sdk:
	@echo "Updating SDK dependencies"
	@export GOFLAGS="" && go get "github.com/solace-iot-team/agent-sdk@SOL-1"


${WORKSPACE}/solace-axway-agent: dep
	@export time=`date +%Y%m%d%H%M%S` && \
	export version=`cat version` && \
	export commit_id=`git rev-parse --short HEAD` && \
	go build -tags static_all \
		-ldflags="-X 'github.com/solace-iot-team/agent-sdk/pkg/cmd.BuildTime=$${time}' \
				-X 'github.com/solace-iot-team/agent-sdk/pkg/cmd.BuildVersion=$${version}' \
				-X 'github.com/solace-iot-teamy/agent-sdk/pkg/cmd.BuildCommitSha=$${commit_id}' \
				-X 'github.com/solace-iot-team/agent-sdk/pkg/cmd.BuildAgentName=Solace-Axway-Agent'" \
		-a -o ${WORKSPACE}/bin/solace-axway-agent ${WORKSPACE}/main.go
# CHANGE_BINARY_NAME - to change the name of the generated binary name, change 'apic_discovery_agent' in the above line				

build:${WORKSPACE}/solace-axway-agent-tux
	@echo "Build complete"

build-tux:
