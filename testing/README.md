# Integration Testing

## Prerequisites
Integration Testing is executed against Solace Cloud Broker.

* Solace ServiceID
* Solace Cloud API Token

## Integration testing on local development box

### Setup testing infrastructure

Testing is done against a local Solace-Connector and Notifier Service. 

* Provide `.env.local` file in `/testing`
    * sample is in `/sample/.env`
    * To convert PEM files into environment variable format use `awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' cert-name.pem` to transform it to a one-liner
* Start Docker-Compose to bring up
    * Solace-Connector Service
    * Notifier Service

### Setup testing configuration

* expose configuration as environment variables
  * Make a copy of `.env.local.agent.integrationtest.sample`
  * Configure accordingly
  * expose as environment variables
* Start testing by `make integrationtest`
    * set environment variables (sample is located in `/testing`)