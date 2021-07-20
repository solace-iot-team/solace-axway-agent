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
	ConnectorURL           string `config:"connector_url"`
	ConnectorAdminUser     string `config:"connector_admin_user"`
	ConnectorAdminPassword string `config:"connector_admin_password"`
	ConnectorOrgUser       string `config:"connector_org_user"`
	ConnectorOrgPassword   string `config:"connector_org_password"`
}

// ValidateCfg - Validates the gateway config
func (c *GatewayConfig) ValidateCfg() (err error) {
	return
}

// ApplyResources - Applies the apply API Server resource to the agent config
func (c *GatewayConfig) ApplyResources(agentResource *v1.ResourceInstance) error {
	return nil
}
