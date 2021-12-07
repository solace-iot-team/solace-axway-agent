[![integration-test](https://github.com/solace-iot-team/solace-axway-agent/actions/workflows/integration-test.yml/badge.svg)](https://github.com/solace-iot-team/solace-axway-agent/actions/workflows/integration-test.yml) 
[![release-version-check](https://github.com/solace-iot-team/solace-axway-agent/actions/workflows/release-version-check.yml/badge.svg)](https://github.com/solace-iot-team/solace-axway-agent/actions/workflows/release-version-check.yml)
# SOLACE AXWAY AGENT

Axway Agent for provisioning AsyncAPIs into Solace Brokers. 

## Concepts and Architecture

* Solace-Axway-Agent polls Axway Central for `subscriptions` (states `subscribing` or  `unsubscribing`).
* Solace-Axway-Agent registers a `Subscription Schema` for Webhooks in Axway Central
* Solace-Axway-Agent polls Axway Central for Axway Catalog Items that are marked as `Webhook Enabled` and assigns the `Subscription Schema`

### Axway Central - Solace-Connector 

### Subscribing AsyncAPIs in Axway

For each `subscribing` subscription Solace-Axway-Agents deploys in Solace-Connector:
* The associated AsyncAPI as `API`
* A `Product` with the `API`
* A `Team` 
* A `TeamApp` with the `Product` assigned to

Solace-Axway-Agent shares by Email and / or HTTP-Notification Call
* Credentials to be used to connect to Solace Broker
  * Username and Password

Solace-Connector provisions into Solace Broker:
* `User` for the `Team`
* `ACLs` assigned to that User
* optionally `Queues`
* optionally `RDPs` (Rest Delivery Points)

### Unsubscribing AsyncAPIs in Axway

For each `unsubscribing` subscription Solace-Axway-Agents undeploys in Solace-Connector
* `TeamApp`
* `Product`

Solace-Connector removes in Solace Broker:
* `User`
* `ACLs`
* optionally `Queues`
* optionally `RDPs`


## Development 
### Prerequisites

* Golang (v 1.16+)
* Make
* Docker and Docker-Compose for integration tests

### Setup Development Environment 

* Solace-Axway-Agent is based on [solace-iot-team/agent-sdk](https://github.com/solace-iot-team/agent-sdk) which is a fork of [Axway/agent-sdk](https://github.com/Axway/agent-sdk) 
  * how to import `agent-sdk` is documented inline in `go.mod`
* Checkout repository
* Build project
  `make build`
* Linter
  `make lint`

### Code Generation
Solace-Connector and Notifier HTTP-Clients are generated. Detailed information is located in `/specs`

### Integration Testing

* Detailed information in `/testing/README.md`

# How to use

## Prerequisites

### Axway Central

* Create Public/Private Key Pair as `PEM`-files
`openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048`
  
* Create Axway Central Service Account
   * Amplify Central `https://central.eu-fr.axway.com` Section `Access`
   * Register Service Account `Add Service Account`
     * Upload / Copy public key PEM 
   
### Solace Environment
* Solace Connector [solace-iot-team/platform-api](https://github.com/solace-iot-team/platform-api)
   * Connector URL
   * Connector Admin username and password
   * Connector Org-Admin username and password
   
For each Axway `Environment` a Solace Connector `Organization` must be provisioned (by convention: same names)  

## Run agent

Configuration of the agent can get provided by a config-file ('solace_axway_agent.yml') or by defining environment variables (still a minimum config-file must be provided, see `sample/sample_min_solace_axway_agent.yml`).


### Prepare `solace_axway_agent.yml` configuration
* Prepare and configure `solace_axway_agent.yml` file. Sample is located in [sample/sample_solace_axway_agent.yml](sample/sample_solace_axway_agent.yml)
* Or set environment variables. Sample is located in `sample/`
  * Although all configuration options can get defined via environment variables, Solace-Axway-Agent must have access to a minimum `solace_axway_agent.yml` configuration file. This file can get located alongside the executable (same directory) or the directory containing the configuration file can get defined as option `--pathConfig`

### Execute `solace-axway-agent` 
* `./solace-axway-agent --pathConfig /Users/jt/myproject/solace/axway-agent/solace-agent-config`

### Check Health

Health checks (accessibility) of Axway Central and Solace Connector can get accessed via a web service exposed by the agent:

Sample of an agent running on localhost:

* `curl http://localhost:8989/status/central`
* `curl http://localhost:8989/status/solace`

### Docker Container
The Solace-Axway-Agent Docker Container is described in this [Dockerfile](Dockerfile).

* Solace-Axway-Agent is executed as user `AGENT` (uid=9999,gid=9999)
* Path `/opt/agent` is read and writeable for user AGENT
