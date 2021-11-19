package integrationtest

// ConnectorConfig - represents the config for middleware
type IntegrationtestConfig struct {
	Org            string `config:"org"`
	OrgEnvName     string `config:"orgEnvName"`
	ServiceId      string `config:"serviceId"`
	TeamName       string `config:"teamName"`
	TeamAppName    string `config:"teamAppName"`
	OrgToken       string `config:"orgToken"`
	ApiName        string `config:"apiName"`
	ApiSpec        string `config:"apiSpec"`
	ApiProductName string `config:"apiProductName"`
	Cleanup        bool   `config:"cleanup"`
}
