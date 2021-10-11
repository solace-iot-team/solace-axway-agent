package config

import (
	"errors"
	v1 "github.com/Axway/agent-sdk/pkg/apic/apiserver/models/api/v1"
	corecfg "github.com/Axway/agent-sdk/pkg/config"
)

// AgentConfig - represents the config for agent
type AgentConfig struct {
	CentralCfg  corecfg.CentralConfig `config:"central"`
	GatewayCfg  *ConnectorConfig      `config:"connector"`
	NotifierCfg *NotifierConfig       `config:"notifier"`
}

// ConnectorConfig - represents the config for gateway
type ConnectorConfig struct {
	corecfg.IConfigValidator
	corecfg.IResourceConfigCallback
	ConnectorURL                string `config:"url"`
	ConnectorAdminUser          string `config:"adminUser"`
	ConnectorAdminPassword      string `config:"adminPassword"`
	ConnectorOrgUser            string `config:"orgUser"`
	ConnectorOrgPassword        string `config:"orgPassword"`
	ConnectorInsecureSkipVerify bool   `config:"acceptInsecureCertificates"`
}

// ConnectorConfig - represents the config for gateway
type NotifierConfig struct {
	corecfg.IConfigValidator
	corecfg.IResourceConfigCallback
	NotifierHealthMessage      string `config:"healthmessage"`
	NotifierURL                string `config:"url"`
	NotifierApiConsumerKey     string `config:"apiConsumerKey"`
	NotifierApiConsumerSecret  string `config:"apiConsumerSecret"`
	NotifierApiAuthType        string `config:"apiAuthType"`
	NotifierInsecureSkipVerify bool   `config:"acceptInsecureCertificates"`
}

// ValidateCfg - Validates the gateway config
func (c *ConnectorConfig) ValidateCfg() (err error) {
	return
}

// ApplyResources - Applies the apply API Server resource to the agent config
func (c *ConnectorConfig) ApplyResources(agentResource *v1.ResourceInstance) error {
	return nil
}

// ValidateCfg - Validates the gateway config
func (c *NotifierConfig) ValidateCfg() (err error) {
	if c.NotifierApiAuthType == "basic" || c.NotifierApiAuthType == "header" {
		//all ok
	} else {
		return errors.New("Configuration notifier.apiAuthType unsupported " + c.NotifierApiAuthType + "]. Only [basic] or [header] supported.")
	}
	return
}

// ApplyResources - Applies the apply API Server resource to the agent config
func (c *NotifierConfig) ApplyResources(agentResource *v1.ResourceInstance) error {
	return nil
}
