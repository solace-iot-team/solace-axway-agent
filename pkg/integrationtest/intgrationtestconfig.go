package integrationtest

// TestConfig - represents the config for middleware
type TestConfig struct {
	Org            string `config:"org"`
	OrgEnvName     string `config:"orgEnvName"`
	ServiceID      string `config:"serviceId"`
	TeamName       string `config:"teamName"`
	TeamAppName    string `config:"teamAppName"`
	OrgToken       string `config:"orgToken"`
	APIName        string `config:"apiName"`
	APISpec        string `config:"apiSpec"`
	APIProductName string `config:"apiProductName"`
	Cleanup        bool   `config:"cleanup"`
}
