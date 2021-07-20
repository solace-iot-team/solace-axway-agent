# Prerequisites

1. Golang
2. Make

# Steps to implement a discovery agent using this stub

1. Locate the commented tag "CHANGE_HERE" for the package import paths in all files and fix them to reference your code path correctly.
2. Run "make dep" to resolve the dependencies. This should resolve all dependency packages and vendor them under ./vendor directory
3. Update Makefile to change the name of generated binary image from *apic_discovery_agent* to the desired name. Locate the comment "CHANGE_BINARY_NAME" and follow the instructions in the comment.
4. Update pkg/cmd/root.go to change the agent yaml file name and description of the agent. Locate *apic_discovery_agent* and *Sample Discovery Agent* and replace with the desired values.
5. Update your specific gateway configuration in pkg/config/config.go
    - Locate *gateway-section* in the sample YAML config file and replace it with the name of your gateway (e.g. MyGateway). Locate this same tag in pkg/cmd/root.go and sample YAML config file and replace it with the same name.
    - To run the sample agent and have it to discover the supplied sample APIs (found in the apis directory), you must change the config YAML file tag named *specPath* in the *gateway-section*. The value must be a fully qualified path to the folder (e.g. /home/me/github.com/someorg/samples/apic_discovery_agent/apis).
    - Define gateway specific config properties in *GatewayConfig* struct. Locate the struct variables *ConfigKey1* & struct *config_key_1* and replace them with your desired config properties.
    - Optionally add config validation for your config values. Locate the *ValidateCfg()* method in config.go and update the implementation to add validation specific to gateway specific config.
    - Optionally add ApplyResources configuration. Locate the *ApplyResources()* method in and update the implementation to add logic to copy ResourceConfiguration values to your gateway specific config.
    - Update the config binding with command line flags in init(). Locate *gateway-section.config_key_1* (by now 'gateway-section' should have been changed to the name of your gateway in a step above) and add replace all config property bindings with the correct values
    - Update the initialization of gateway specific config by parsing the binded properties. Locate *ConfigKey1* & *gateway-section.config_key_1* (again, 'gateway-section' should have been changed to the name of your gateway in a step above) and add/replace all config properties
6. Update pkg/gateway/client.go to implement the logic to discover and fetch the details related of the APIs.
    - Locate *DiscoverAPIs()* method and implement the logic
    - Locate *buildServiceBody()* method and update the Set*() method according to the API definition from gateway
7. Run "make build" to build the agent
8. Rename *apic_discovery_agent.yml* file to the agent name you previously specified in pkg/cmd/root.go and set up the agent config in the file.
9. Copy the YAML config file to the *bin* directory.
10. Execute the agent by running the binary file generated under *bin* directory.

Reference: [SDK Documentation - Building Discovery Agent](https://github.com/Axway/agent-sdk/blob/main/docs/discovery/index.md)
