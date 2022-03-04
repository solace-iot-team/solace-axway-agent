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

// BootstrappingConfig - represents the config for bootstrapping
type BootstrappingConfig struct {
	corecfg.IConfigValidator
	corecfg.IResourceConfigCallback
	PublishSubscriptionSchema         bool `config:"publishSubscriptionSchema"`
	ProcessSubscriptionSchema         bool `config:"processSubscriptionSchema"`
	ProcessSubscriptionSchemaInterval int  `config:"processSubscriptionSchemaInterval"`
}

// ConnectorConfig - represents the config for middleware
type ConnectorConfig struct {
	corecfg.IConfigValidator
	corecfg.IResourceConfigCallback
	ConnectorURL                string `config:"url"`
	ConnectorProxyURL           string `config:"proxyUrl"`
	ConnectorAdminUser          string `config:"adminUser"`
	ConnectorAdminPassword      string `config:"adminPassword"`
	ConnectorOrgUser            string `config:"orgUser"`
	ConnectorOrgPassword        string `config:"orgPassword"`
	ConnectorInsecureSkipVerify bool   `config:"acceptInsecureCertificates"`
	ConnectorLogBody            bool   `config:"logBody"`
	ConnectorLogHeader          bool   `config:"logHeader"`
	ConnectorOrgMapping         string `config:"orgMapping"`
}

// NotifierConfig - represents the config for Notifier
type NotifierConfig struct {
	corecfg.IConfigValidator
	corecfg.IResourceConfigCallback
	NotifierEnabled            bool   `config:"enabled"`
	NotifierHealthMessage      string `config:"healthmessage"`
	NotifierURL                string `config:"url"`
	NotifierProxyURL           string `config:"proxyUrl"`
	NotifierAPIConsumerKey     string `config:"apiConsumerKey"`
	NotifierAPIConsumerSecret  string `config:"apiConsumerSecret"`
	NotifierAAPIAuthType       string `config:"apiAuthType"`
	NotifierInsecureSkipVerify bool   `config:"acceptInsecureCertificates"`
}

// ValidateCfg - Validates the middleware config
func (c *ConnectorConfig) ValidateCfg() (err error) {
	return
}

// ApplyResources - Applies the apply API Server resource to the agent config
func (c *ConnectorConfig) ApplyResources(agentResource *v1.ResourceInstance) error {
	return nil
}

// ValidateCfg - Validates the middleware config
func (c *NotifierConfig) ValidateCfg() (err error) {
	if c.NotifierAAPIAuthType == "basic" || c.NotifierAAPIAuthType == "header" {
		//all ok
	} else {
		return errors.New("Configuration notifier.apiAuthType unsupported " + c.NotifierAAPIAuthType + "]. Only [basic] or [header] supported.")
	}
	return
}

// ApplyResources - Applies the apply API Server resource to the agent config
func (c *NotifierConfig) ApplyResources(agentResource *v1.ResourceInstance) error {
	return nil
}
