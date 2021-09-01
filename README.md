# SOLACE AXWAY AGENT

Axway Agent for provisioning AsyncAPI to Solace Brokers. 

# Prerequisites

* Golang (v 1.13+)
* Make

# How to build

* Checkout
* Build project 
  * TODO detailed description what to do
   
# How to use

## Prerequisites

### Axway
* Create Public/Private Key Pair as `PEM`-files
`openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048`
  
* Create Axway Central Service Account
   * Amplify Central `https://central.eu-fr.axway.com` Section `Access`
   * Register Service Account `Add Service Account`
     * Upload / Copy public key PEM 
   
### Solace Environment
* Solace Connector Credentials
   * Connector URL
   * Connector Admin username and password
   * Connector Org-Admin username and password
   
For each Axway `Environment` a Solace Connector `Organization` must be provisioned. 

## Run agent

Configuration of the agent can get provided by an config-file ('solace_axway_agent.yml') or by defining environment variables (still a minimum config-file must be provided).


### Prepare `solace-axway-agent.yml` configuration
* Prepare and configure `solace-axway-agent.yml` file. Sample provided in this repo.
* Or set environment variables

### Execute `solace-axway-agent` 
* `./solace-axway-agent --pathConfig /Users/jt/myproject/solace/axway-agent/solace-agent-config`

### Check Health

Health checks (accessibility) of Axway Central and Solace Connector can get accessed via a web service exposed by the agent:

Sample of an agent running on localhost:

* `curl http://localhost:8989/status/central`
* `curl http://localhost:8989/status/solace`


# Concepts

* An Axway Environment is mapped against a Solace Connector Organization (env-name = org-name)