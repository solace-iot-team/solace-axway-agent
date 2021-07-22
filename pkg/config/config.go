package config

import (
	v1 "github.com/solace-iot-team/agent-sdk/pkg/apic/apiserver/models/api/v1"
	corecfg "github.com/solace-iot-team/agent-sdk/pkg/config"
)

// AgentConfig - represents the config for agent
type AgentConfig struct {
	CentralCfg corecfg.CentralConfig `config:"central"`
	GatewayCfg *GatewayConfig        `config:"gateway-section"`
}

// GatewayConfig - represents the config for gateway
type GatewayConfig struct {
	corecfg.IConfigValidator
	corecfg.IResourceConfigCallback
	ConnectorURL           string `config:"connectorUrl"`
	ConnectorAdminUser     string `config:"connectorAdminUser"`
	ConnectorAdminPassword string `config:"connectorAdminPassword"`
	ConnectorOrgUser       string `config:"connectorOrgUser"`
	ConnectorOrgPassword   string `config:"connectorOrgPassword"`
}

// ValidateCfg - Validates the gateway config
func (c *GatewayConfig) ValidateCfg() (err error) {
	return
}

// ApplyResources - Applies the apply API Server resource to the agent config
func (c *GatewayConfig) ApplyResources(agentResource *v1.ResourceInstance) error {
	return nil
}
