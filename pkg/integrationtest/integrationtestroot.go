package integrationtest

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/Axway/agent-sdk/pkg/cmd"
	corecmd "github.com/Axway/agent-sdk/pkg/cmd"
	corecfg "github.com/Axway/agent-sdk/pkg/config"
	"github.com/Axway/agent-sdk/pkg/notify"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/solace-iot-team/solace-axway-agent/pkg/config"
	"github.com/solace-iot-team/solace-axway-agent/pkg/connector"
	"github.com/solace-iot-team/solace-axway-agent/pkg/middleware"
	"github.com/solace-iot-team/solace-axway-agent/pkg/notification"
	"github.com/solace-iot-team/solace-axway-agent/pkg/solace"
	"strings"
	"testing"
)

// RootCmd - Agent root command
var RootCmd cmd.AgentRootCmd
var bootstrappingConifg *config.BootstrappingConfig
var connectorConfig *config.ConnectorConfig
var iCfg *TestConfig
var notifierConfig *config.NotifierConfig

var sendEmail bool = false
var sendNotification bool = false

func init() {
	//log.SetLevel(logrus.TraceLevel)
	// Create new root command with callbacks to initialize the agent config and command execution.
	// The first parameter identifies the name of the yaml file that agent will look for to load the config
	RootCmd = corecmd.NewRootCmd(
		"solace_axway_agent_test", // Name of the yaml file
		"Solace Axway Agent",      // Agent description
		initConfig,                // Callback for initializing the agent config
		run,                       // Callback for executing the agent
		corecfg.DiscoveryAgent,    // Agent Type (Discovery or Traceability)
	)
}

// Callback that agent will call to process the execution
func run() error {
	//nothing to do
	return nil
}

// ExecuteIntegrationTestMiddleware executes Middleware Integration Tests
func ExecuteIntegrationTestMiddleware() error {
	apiSpec := iCfg.APISpec

	container := TestSubscriptionContainer{
		valid:                         true,
		revisionName:                  "int-test-prod-2",
		subscriptionMetadataScopeName: iCfg.OrgEnvName,
		externalAPIName:               "int-test-mw-1",
		externalAPIID:                 "int-test-mw-1",
		apiSpec:                       string(apiSpec),
		//permissions map[string]int{"foo": 1, "bar": 2}
		serviceAttributes:         map[string]string{"att1": "value1,value2", "att2": "value3"},
		subscriptionName:          "int-sub-mw-1",
		subscriptionID:            "int-sub-mw-1-id",
		subscriptionOwningTeamID:  "int-sub-ws-1-team-id",
		subscriptionCatalogItemID: "int-sub-ws-1-cat-id",
		subscriptionProperties: map[string]string{
			solace.SolaceHTTPMethod:               "post",
			solace.SolaceCallback:                 "http://some.callback.org",
			solace.SolaceAuthenticationMethod:     "basic",
			solace.SolaceAuthenticationIdentifier: "username",
			solace.SolaceAuthenticationSecret:     "secret",
			solace.SolaceInvocationOrder:          "parallel",
		},
		catalogItemName: "int-sub-ws-1-cat-name",
		serviceInstanceSpecEndpoints: []middleware.AxwayEndpoint{
			{
				Host:     "mr1i5g7tif6z9h.messaging.solace.cloud",
				Port:     1883,
				Protocol: "mqtt",
			},
		},
	}

	middleware := middleware.SubscriptionMiddleware{
		AxSub: &container,
	}

	err := executeTestCRUDOrganization()
	if err != nil {
		log.Errorf("Error creating organization", err)
		return err
	}
	err = executeTestCRUDEnvironment()
	if err != nil {
		log.Errorf("Error creating environment", err)
		return err
	}

	err = middleware.ProcessSubscription()
	if err != nil {
		log.Errorf("Error processing subscription", err)
		return err
	}

	err = middleware.ProcessUnsubscribeSubscription()
	if err != nil {
		log.Errorf("Error processing unsubscription", err)
		return err
	}
	return nil
}

// TestSubscriptionContainer - mocks Axway Subscription Data
type TestSubscriptionContainer struct {
	valid                            bool
	revisionName                     string
	serviceInstanceMetadataScopeName string
	externalAPIID                    string
	externalAPIName                  string
	apiSpec                          string
	serviceAttributes                map[string]string
	subscriptionName                 string
	subscriptionAPIServiceName       string
	subscriptionID                   string
	subscriptionOwningTeamID         string
	subscriptionCatalogItemID        string
	subscriptionMetadataScopeName    string
	subscriptionProperties           map[string]string
	serviceInstanceSpecEndpoints     []middleware.AxwayEndpoint

	catalogItemName             string
	subscriberEmailAddress      string
	subscriberUserName          string
	subscriptionCredentials     *connector.SolaceCredentialsDto
	solaceCallbackAPI           bool
	solaceAsyncAPIAppInternalID string
}

// LogText - Extracts Logging Details
func (c *TestSubscriptionContainer) LogText() string {
	return fmt.Sprintf("[Environment/Org:%s] [Team:%s] [API-Product:%s] [Application:%s] [API:%s]", c.GetEnvironmentName(), c.GetSubscriptionOwningTeamID(), c.GetRevisionName(), c.GetSubscriptionID(), c.GetRevisionName())
}

// GetSolaceAsyncAPIAppInternalID getter
func (c *TestSubscriptionContainer) GetSolaceAsyncAPIAppInternalID() string {
	return c.solaceAsyncAPIAppInternalID
}

// GetCatalogItemName getter
func (c *TestSubscriptionContainer) GetCatalogItemName() string {
	return c.catalogItemName
}

// SetSolaceAsyncAPIAppInternalID getter
func (c *TestSubscriptionContainer) SetSolaceAsyncAPIAppInternalID(id string) {
	c.solaceAsyncAPIAppInternalID = id
}

// SetSubscriptionCredentials getter
func (c *TestSubscriptionContainer) SetSubscriptionCredentials(credentials *connector.SolaceCredentialsDto) {
	c.subscriptionCredentials = credentials
}

// GetSubscriptionCredentials getter
func (c *TestSubscriptionContainer) GetSubscriptionCredentials() *connector.SolaceCredentialsDto {
	return c.subscriptionCredentials
}

// GetSubscriberEmailAddress - Returns Email
func (c *TestSubscriptionContainer) GetSubscriberEmailAddress() string {
	return c.subscriberEmailAddress
}

// GetSubscriberUserName - Returns Username
func (c *TestSubscriptionContainer) GetSubscriberUserName() string {
	return c.subscriberUserName
}

// GetRevisionName - Facade to retrieve RevisionName
func (c *TestSubscriptionContainer) GetRevisionName() string {
	return c.revisionName
}

// IsEnvironmentDefined - Facade to check if environment is set in Service Instance
func (c *TestSubscriptionContainer) IsEnvironmentDefined() bool {
	return true
}

// GetEnvironmentName - Facade to get environment name (Service Instance Scope Name)
func (c *TestSubscriptionContainer) GetEnvironmentName() string {
	return c.GetServiceInstanceMetadataScopeName()
}

// IsExternalAPIIDDefined - Facade to check if External API ID is set
func (c *TestSubscriptionContainer) IsExternalAPIIDDefined() bool {
	return c.GetExternalAPIID() != ""
}

// IsExternalAPINameDefined - Facade to check if External API Name is set
func (c *TestSubscriptionContainer) IsExternalAPINameDefined() bool {
	return c.GetExternalAPIName() != ""
}

// GetExternalAPIID - Facade to get External API ID
func (c *TestSubscriptionContainer) GetExternalAPIID() string {
	return c.externalAPIID
}

// GetExternalAPIName - Facade to get External API Name
func (c *TestSubscriptionContainer) GetExternalAPIName() string {
	return c.externalAPIName
}

// GetAPISpec - Facade ti get API Spec (AsyncAPI spec)
func (c *TestSubscriptionContainer) GetAPISpec() string {
	return c.apiSpec
}

// GetServiceAttributes getter
func (c *TestSubscriptionContainer) GetServiceAttributes() map[string]string {
	return c.serviceAttributes
}

// GetSubscriptionName getter
func (c *TestSubscriptionContainer) GetSubscriptionName() string {
	return c.subscriptionName
}

// GetSubscriptionAPIServiceName getter
func (c *TestSubscriptionContainer) GetSubscriptionAPIServiceName() string {
	return c.subscriptionAPIServiceName
}

// GetSubscriptionID getter
func (c *TestSubscriptionContainer) GetSubscriptionID() string {
	return c.subscriptionID
}

// GetSubscriptionOwningTeamID getter
func (c *TestSubscriptionContainer) GetSubscriptionOwningTeamID() string {
	return c.subscriptionOwningTeamID
}

// GetSubscriptionCatalogItemID getter
func (c *TestSubscriptionContainer) GetSubscriptionCatalogItemID() string {
	return c.subscriptionCatalogItemID
}

// GetSubscriptionPropertyValue getter
func (c *TestSubscriptionContainer) GetSubscriptionPropertyValue(key string) string {
	return c.subscriptionProperties[key]
}

// GetServiceInstanceMetadataScopeName getter
func (c *TestSubscriptionContainer) GetServiceInstanceMetadataScopeName() string {
	return c.subscriptionMetadataScopeName
}

// GetServiceInstanceSpecEndpoints getter
func (c *TestSubscriptionContainer) GetServiceInstanceSpecEndpoints() []middleware.AxwayEndpoint {
	return c.serviceInstanceSpecEndpoints
}

// TestSubscriptionMiddleware middleware
type TestSubscriptionMiddleware struct {
	valid bool
	AxSub middleware.AxwaySubscription
}

// ExecuteIntegrationTestsConnector executes tests
func ExecuteIntegrationTestsConnector(t *testing.T) error {
	t.Logf("=== Starting Integration Tests against Connector Server:%s with Org:%s", connectorConfig.ConnectorURL, iCfg.Org)
	err := executeTestHealthCheck()
	if err != nil {
		return err
	}

	err = executeTestCRUDOrganization()
	if err != nil {
		return err
	}

	err = executeTestCRUDEnvironment()
	if err != nil {
		return err
	}
	err = executeTestCRUDEnvironment()
	if err != nil {
		return err
	}

	err = executeTestCRUDAPI()
	if err != nil {
		return err
	}
	err = executeTestCRUDAPI()
	if err != nil {
		return err
	}

	err = executeTestCRUDAPIProduct()
	if err != nil {
		return err
	}
	err = executeTestCRUDAPIProduct()
	if err != nil {
		return err
	}

	err = executeTestCRUDTeam()
	if err != nil {
		return err
	}
	err = executeTestCRUDTeam()
	if err != nil {
		return err
	}

	err = executeTestCRUDTeamApp(false, false)
	if err != nil {
		return err
	}
	err = executeTestCRUDTeamApp(true, false)
	if err != nil {
		return err
	}
	err = executeTestCRUDTeamApp(true, true)
	if err != nil {
		return err
	}

	if iCfg.Cleanup {
		//cleanup
		err = executeDeleteOrganization()
		if err != nil {
			return err
		}
		log.Infof("Removed organization:%s from Connector", iCfg.Org)
	}
	t.Logf("=== DONE Integration Tests against Connector Server:%s with Org:%s", connectorConfig.ConnectorURL, iCfg.Org)
	return nil

}

func executeTestCRUDTeamApp(addWebhook bool, addTrustedCNs bool) error {
	log.Tracef("connector.GetOrgConnector().IsTeamAppAvailable")
	found, err := connector.GetOrgConnector().IsTeamAppAvailable(iCfg.Org, iCfg.TeamName, iCfg.TeamAppName)
	if err != nil {
		log.Tracef("IsTeamAppAvailable faulted")
		return err
	}
	if found {
		log.Tracef("TeamApp found")
		log.Tracef("connector.GetOrgConnector().RemoveTeamApp")
		err := connector.GetOrgConnector().RemoveTeamApp(iCfg.Org, iCfg.TeamName, iCfg.TeamAppName)
		if err != nil {
			log.Tracef("RemoveTeamApp faulted")
			return err
		}
		log.Tracef("TeamApp deleted")
	}

	listProducts := make([]string, 0)
	listProducts = append(listProducts, iCfg.APIProductName)
	var webHooks *connector.SolaceWebhook = nil
	if addWebhook {
		if addTrustedCNs {
			listCNs := strings.Split("*.solace.com,my.company.org", ",")
			webHooks = &connector.SolaceWebhook{
				HTTPMethod:               "post",
				CallbackURL:              "http://does.not.work",
				AuthenticationMethod:     "BasicAuthentication",
				AuthenticationSecret:     "secret123",
				AuthenticationIdentifier: "identifier",
				InvocationOrder:          "parallel",
				TrusedCNs:                listCNs,
			}
		} else {
			webHooks = &connector.SolaceWebhook{
				HTTPMethod:               "post",
				CallbackURL:              "http://does.not.work",
				AuthenticationMethod:     "BasicAuthentication",
				AuthenticationSecret:     "secret123",
				AuthenticationIdentifier: "identifier",
				InvocationOrder:          "parallel",
				TrusedCNs:                make([]string, 0),
			}
		}
	}
	credentials, err := connector.GetOrgConnector().PublishTeamApp(iCfg.Org, iCfg.TeamName, iCfg.TeamAppName, iCfg.TeamAppName, listProducts, webHooks)
	if credentials == nil {
		log.Tracef("Credentials as result are missing")
		return errors.New("Credentials as result are missing")
	}
	if credentials.Secret == nil {
		log.Tracef("Credentials.Secret as result are missing")
		return errors.New("Credentials.Secret as result are missing")
	}
	return nil
}

func executeTestCRUDTeam() error {
	log.Tracef("connector.GetOrgConnector().IsTeamAvailable")
	found, err := connector.GetOrgConnector().IsTeamAvailable(iCfg.Org, iCfg.TeamName)
	if err != nil {
		log.Tracef("IsTeamAvailable faulted")
		return err
	}
	if found {
		log.Tracef("Team found")
		log.Tracef("connector.GetOrgConnector().DeleteTeam")
		err := connector.GetOrgConnector().DeleteTeam(iCfg.Org, iCfg.TeamName)
		if err != nil {
			log.Tracef("DeleteTeam faulted")
			return err
		}
		log.Tracef("Team deleted")
	}

	log.Tracef("connector.GetOrgConnector().PublishTeam")
	err = connector.GetOrgConnector().PublishTeam(iCfg.Org, iCfg.TeamName)
	if err != nil {
		log.Tracef("Publish Team faulted")
		return err
	}
	log.Tracef("Created Team")

	return nil

}

func executeTestCRUDEnvironment() error {
	log.Tracef("connector.GetOrgConnector().GetListEnvironments /%s", iCfg.Org)
	listEnvs, err := connector.GetOrgConnector().GetListEnvironments(iCfg.Org)
	if err != nil {
		log.Tracef("GetListEnvironments faulted")
		return err
	}
	foundEnv := false
	for _, env := range listEnvs {
		if env.Name == iCfg.OrgEnvName {
			foundEnv = true
		}
	}
	if foundEnv {
		log.Tracef("connector.GetOrgConnector().DeleteEnvironment /%/%", iCfg.Org, iCfg.OrgEnvName)
		success, err := connector.GetOrgConnector().DeleteEnvironment(iCfg.Org, iCfg.OrgEnvName)
		if err != nil {
			log.Tracef("DeleteEnvironments faulted")
			return err
		}
		if !success {
			log.Tracef("DeleteEnvironment was not HTTP-Code < 300")
			return errors.New("DeleteEnvironment was not HTTP < 300")
		}
		log.Trace("Deleted Environment: %s", iCfg.OrgEnvName)
	}
	protocolVersions := make([]map[string]string, 0)
	protocolVersion := map[string]string{
		"name":    "mqtt",
		"version": "3.1.1",
	}
	protocolVersions = append(protocolVersions, protocolVersion)
	log.Tracef("connector.GetOrgConnector().CreateEnvironment /%s/%s", iCfg.Org, iCfg.OrgEnvName)
	err = connector.GetOrgConnector().CreateEnvironment(iCfg.Org, iCfg.OrgEnvName, "Integration Test Environment", iCfg.ServiceID, protocolVersions)
	if err != nil {
		log.Tracef("Could not create Environment")
		return err
	}
	log.Tracef("Environment created")
	return nil
}

func executeTestCRUDAPIProduct() error {
	log.Tracef("connector.GetOrgConnector().IsAPIProductAvailable /%s/%s", iCfg.Org, iCfg.APIProductName)
	found, err := connector.GetOrgConnector().IsAPIProductAvailable(iCfg.Org, iCfg.APIProductName)
	if err != nil {
		log.Tracef("IsAPIProductAvailable faulted")
		return err
	}
	if found {
		log.Tracef("Found ApiProduct: %s", iCfg.APIProductName)
		log.Tracef("connector.GetOrgConnector().RemoveAPIProduct /%s/%s", iCfg.Org, iCfg.APIProductName)
		err := connector.GetOrgConnector().RemoveAPIProduct(iCfg.Org, iCfg.APIProductName, false)
		if err != nil {
			log.Tracef("Could not delete ApiProduct")
			return err
		}
		log.Tracef("ApiProduct: %S deleted", iCfg.APIName)
	}

	permissions := map[string]string{
		"abc": "efg",
	}
	envNames := make([]string, 0)
	apiNames := make([]string, 0)
	protocols := make([]connector.Protocol, 0)

	envNames = append(envNames, iCfg.OrgEnvName)
	apiNames = append(apiNames, iCfg.APIName)
	version := connector.CommonVersion("3.1.1")
	protocols = append(protocols, connector.Protocol{
		Name:    "mqtt",
		Version: &version,
	})
	log.Tracef("connector.GetOrgConnector().PublishAPIProduct /%s/%s", iCfg.Org, iCfg.APIProductName)
	err = connector.GetOrgConnector().PublishAPIProduct(iCfg.Org, iCfg.APIProductName, apiNames, envNames, protocols, permissions)
	if err != nil {
		log.Tracef("Could not create APIProduct")
		return err
	}
	log.Tracef("Created APIProduct")
	return nil
}

func executeTestCRUDAPI() error {
	log.Tracef("connector.GetOrgConnector().IsAPIAvailable /%s/%s", iCfg.Org, iCfg.APIName)
	found, err := connector.GetOrgConnector().IsAPIAvailable(iCfg.Org, iCfg.APIName)
	if err != nil {
		log.Tracef("IsAPIAvailable faulted")
		return err
	}
	if found {
		log.Tracef("Found API: %s", iCfg.APIName)
		log.Tracef("connector.GetOrgConnector().RemoveAPI /%s/%s", iCfg.Org, iCfg.APIName)
		err := connector.GetOrgConnector().RemoveAPI(iCfg.Org, iCfg.APIName, false)
		if err != nil {
			log.Tracef("Could not delete API")
			return err
		}
		log.Tracef("API: %S deleted", iCfg.APIName)
	}
	apiSpec, errDecode := base64.StdEncoding.DecodeString(iCfg.APISpec)
	if errDecode != nil {
		log.Tracef("Could not base64 decode APISpec")
		return errDecode
	}
	log.Tracef("connector.GetOrgConnector().PublishAPI /%s/%s", iCfg.Org, iCfg.APIName)
	err = connector.GetOrgConnector().PublishAPI(iCfg.Org, iCfg.APIName, apiSpec)
	if err != nil {
		log.Tracef("Could not publish API %s", iCfg.APIName)
		return err
	}
	log.Tracef("API: %s published", iCfg.APIName)
	return nil
}

func executeDeleteOrganization() error {
	found, err := connector.GetOrgConnector().IsOrgRegistered(iCfg.Org)
	if err != nil {
		log.Tracef("IsOrgRegistered faulted")
		return err
	}
	if found {
		log.Tracef("Found Org:%s and try to delete it", iCfg.Org)
		ok, err := connector.GetOrgConnector().DeleteOrg(iCfg.Org)
		if err != nil {
			log.Tracef("Deleting Org throws Error")
			return err
		}
		if !ok {
			log.Tracef("Could not delete Org")
			return errors.New("Could not create Org")
		}
		log.Tracef("Org %s deleted", iCfg.Org)
	} else {
		log.Infof("Could not find org:%s", iCfg.Org)
		return errors.New("Coult not find Organziation")
	}
	return nil
}

func executeTestCRUDOrganization() error {
	found, err := connector.GetOrgConnector().IsOrgRegistered(iCfg.Org)
	if err != nil {
		log.Tracef("IsOrgRegistered faulted")
		return err
	}
	if found {
		log.Tracef("Found Org:%s and try to delete it", iCfg.Org)
		ok, err := connector.GetOrgConnector().DeleteOrg(iCfg.Org)
		if err != nil {
			log.Tracef("Deleting Org throws Error")
			return err
		}
		if !ok {
			log.Tracef("Could not delete Org")
			return errors.New("Could not create Org")
		}
		log.Tracef("Org %s deleted", iCfg.Org)
	} else {
		log.Infof("Could not find org:%s", iCfg.Org)
	}
	orgToken := iCfg.OrgToken
	test := make([]interface{}, 1)
	test[0] = orgToken
	ok, err := connector.GetOrgConnector().CreateOrg(iCfg.Org, &test[0])
	if err != nil {
		log.Tracef("Creating Org throws Error")
		return err
	}
	if !ok {
		log.Tracef("Could not create Org")
		return errors.New("Could not create Org")
	}
	log.Tracef("Org %s created", iCfg.Org)
	return nil
}

func executeTestHealthCheck() error {
	healthCheck, err := connector.GetOrgConnector().IsHealthCheck()
	if err != nil {
		log.Tracef("Health Check of Connector throws Error")
		return err
	}
	if !healthCheck {
		return errors.New("Health Check of Connector was not successfull")
	}
	log.Infof("Health Check of Connector was successfull")
	return nil
}

// DerefString dereferences pointer, return empty string for NIL
func DerefString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

// Callback that agent will call to initialize the config. CentralConfig is parsed by Agent SDK
// and passed to the callback allowing the agent code to access the central config
func initConfig(centralConfig corecfg.CentralConfig) (interface{}, error) {
	//configure SMTP notifications central.subscriptions.notifications.type must be set to smtp
	if len(centralConfig.GetSubscriptionConfig().GetNotificationTypes()) == 1 {
		if centralConfig.GetSubscriptionConfig().GetNotificationTypes()[0] == "SMTP" {
			notify.SetSubscriptionConfig(centralConfig.GetSubscriptionConfig())
			sendEmail = true
			log.Infof("SMTP Notification enabled")
		} else {
			log.Infof("SMTP Notification not enabled - ignoring %s", centralConfig.GetSubscriptionConfig().GetNotificationTypes()[0])
		}
	} else {
		log.Infof("SMTP Notification not configured.")
	}

	rootProps := RootCmd.GetProperties()

	// BootstrappingConfig - represents the config for bootstrapping
	bootstrappingConifg = &config.BootstrappingConfig{
		PublishSubscriptionSchema:         rootProps.BoolPropertyValue("bootstrapping.publishSubscriptionSchema"),
		ProcessSubscriptionSchema:         rootProps.BoolPropertyValue("bootstrapping.processSubscriptionSchema"),
		ProcessSubscriptionSchemaInterval: rootProps.IntPropertyValue("bootstrapping.processSubscriptionSchemaInterval"),
	}

	// Parse the config from bound properties and setup middleware config
	connectorConfig = &config.ConnectorConfig{
		ConnectorURL:                rootProps.StringPropertyValue("connector.url"),
		ConnectorProxyURL:           rootProps.StringPropertyValue("connector.proxyUrl"),
		ConnectorAdminUser:          rootProps.StringPropertyValue("connector.adminUser"),
		ConnectorAdminPassword:      rootProps.StringPropertyValue("connector.adminPassword"),
		ConnectorOrgUser:            rootProps.StringPropertyValue("connector.orgUser"),
		ConnectorOrgPassword:        rootProps.StringPropertyValue("connector.orgPassword"),
		ConnectorInsecureSkipVerify: rootProps.BoolPropertyValue("connector.acceptInsecureCertificates"),
		ConnectorLogBody:            rootProps.BoolPropertyValue("connector.logBody"),
		ConnectorLogHeader:          rootProps.BoolPropertyValue("connector.logHeader"),
	}

	notifierConfig = &config.NotifierConfig{
		NotifierEnabled:            rootProps.BoolPropertyValue("notifier.enabled"),
		NotifierProxyURL:           rootProps.StringPropertyValue("notifier.proxyUrl"),
		NotifierHealthMessage:      rootProps.StringPropertyValue("notifier.healthmessage"),
		NotifierURL:                rootProps.StringPropertyValue("notifier.url"),
		NotifierAPIConsumerKey:     rootProps.StringPropertyValue("notifier.apiConsumerKey"),
		NotifierAPIConsumerSecret:  rootProps.StringPropertyValue("notifier.apiConsumerSecret"),
		NotifierAAPIAuthType:       rootProps.StringPropertyValue("notifier.apiAuthType"),
		NotifierInsecureSkipVerify: rootProps.BoolPropertyValue("notifier.acceptInsecureCertificates"),
	}

	agentConfig := config.AgentConfig{
		CentralCfg:  centralConfig,
		GatewayCfg:  connectorConfig,
		NotifierCfg: notifierConfig,
	}

	iCfg = &TestConfig{
		Org:            rootProps.StringPropertyValue("integrationtest.org"),
		OrgEnvName:     rootProps.StringPropertyValue("integrationtest.orgEnvName"),
		OrgToken:       rootProps.StringPropertyValue("integrationtest.orgToken"),
		ServiceID:      rootProps.StringPropertyValue("integrationtest.serviceId"),
		TeamName:       rootProps.StringPropertyValue("integrationtest.teamName"),
		APIName:        rootProps.StringPropertyValue("integrationtest.apiName"),
		APISpec:        rootProps.StringPropertyValue("integrationtest.apiSpec"),
		APIProductName: rootProps.StringPropertyValue("integrationtest.apiProductName"),
		TeamAppName:    rootProps.StringPropertyValue("integrationtest.teamAppName"),
		Cleanup:        rootProps.BoolPropertyValue("integrationtest.cleanup"),
	}

	log.Tracef("Org:%s OrgEnvName:%s  ServiceID:%s", iCfg.Org, iCfg.OrgEnvName, iCfg.ServiceID)

	// initialize solace-connector
	err := connector.Initialize(connectorConfig)
	if err != nil {
		log.Errorf("Could not initialize Solace Connector")
		panic(err)
	}

	// initialize solace notifier
	if notifierConfig.NotifierEnabled {
		//Initializse also registers itself with HealthChecker
		errNotification := notification.Initialize(notifierConfig)
		if errNotification != nil {
			log.Errorf("Could not initialize Solace Notifier")
			panic(errNotification)
		}
		log.Infof("Solace Notifier enabled")
	} else {
		log.Info("Solace Notifier disabled")
	}
	return agentConfig, nil
}

// GetAgentConfig getter
func GetAgentConfig() *config.ConnectorConfig {
	// GetAgentConfig - Returns the agent config
	return connectorConfig
}
