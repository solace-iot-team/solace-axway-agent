# Release Notes

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
