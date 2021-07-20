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

### Prepare `solace-axway-agent.yml` configuration
* Prepare and configure `solace-axway-agent.yml` file. Sample provided in this repo.

### Execute `solace-axway-agent`
* `./solace-axway-agent --pathConfig /Users/jt/myproject/solace/axway-agent/solace-agent-config`

