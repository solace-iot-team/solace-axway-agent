# Release Notes

## Version 0.0.20

### Features

* **Provioning of Queues**
  * Queues will get provisioned per subscriber if `solace-queue-require` attribute and further attribtes got defined for an AsyncAPI service

### Fixes

* no bug fixes

## Version 0.0.19

### Features

* **Connector Organization Mapping**
  * 'connector.orgMapping' introduced as optional configuration to define Solace-Connector organization name instead of sticking to default convention with Axway-Environment-Name = Connector-Org-Name  

* **Solace SMF Protocol Support**
  * Solace SMF, Secure SMF and Compressed SMF protocols can get used as Axway Endpoint Protocols and will get provisioned into Solace-Connector
  

## Version 0.0.18

### Features

* **ClientOrigin**
  * 'ClientOrigin' can get provided as Attribute for Axway Subscriptions
    * annotating an Axway Central API-Service with `solace-webhook-enabled=true` as attribute triggers assignment of corresponding subscription schema 
    * annotating an Axway Central API-Service with `solace-clientorigin-enabled=true` as attribute triggers assignment of corresponding subscription schema
    * during subscribing to such an API the subscriber can add `ClientOrigin` like an IP-Address
    * `ClientOrigin` will get added as `Solace-Connector Application Attribute` for further processing
   ```
     Solace-Conenctor App 
     ...
     "attributes": [
     {
       "name": "ClientOrigin",
       "value": "some.dns.name or 123.123.123.123"
     }]
  ```
### Fixes
* no bug fixes

## Version 0.0.17

### Features
* no new features

### Fixes
* **Axway Environment filter**
  * Fixed Axway Environment as configured in Solace-Axway-Agent was not taken into account, all subscriptions within an Axway organization got processed


## Version 0.0.16

### Features
* **changed API-Mapping to Axway Revision.ID (instead of Revision.Name)**
  - Assigning ApiServiceRevision.Metadata.Id to Solace-Connector API-Name and API-Product-Name
* **Removed strict mapping check of Solace-Connector environment protocols**
  - Mapping of Axway Endpoint to Solace-Connector environment based on hostname 

## Version 0.0.15

### Features
* **Debugging Information Public-/Private-Key Configuration**
  - Logging (Trace/Error) more detailed information about Pubic/-Private-Key Configuration and internal validation results

## Version 0.0.14

### Features
* **Release**
  - Default Dockerfile adds agent user to root group


## Version 0.0.13

### Features
* **HTTP-Proxy support**
  - HTTP-Proxies can get defined for Axway Client, Solace-Connector Client and Notifier Client
  - Configuration in [sample_solace_axway_agent.yml](sample/sample_solace_axway_agent.yml) as dedicated environment variables / configuration fields


## Version 0.0.12

### Features
* **Release**
    - added docker image latest tag to docker hub image

## Version 0.0.11

### Features
* **Subscription Schema**
    - Registers `Axway Subscription Schema` in Axway Central
    - Assigns `Axway Subscription Schema` to `Axway Catalog Item` with attribute `solace-webhook-enabled==true`
* **Subscribing and Unsubscribing Subscriptions**
    - Processes `Subscribing` AsyncAPI subscriptions and provisions into Solace-Connector
    - Processes `Unsubscribing` AsyncAPI subscriptions and removes them from Solace-Connector
  
### Fixes
* no fixes
