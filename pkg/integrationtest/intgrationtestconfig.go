package integrationtest

// ConnectorConfig - represents the config for gateway
type IntegrationtestConfig struct {
	Org      string `config:"org"`
	OrgToken string `config:"orgToken"`
}
