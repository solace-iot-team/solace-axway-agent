package integrationtest

import (
	"encoding/base64"
	"errors"
	"github.com/Axway/agent-sdk/pkg/cmd"
	corecmd "github.com/Axway/agent-sdk/pkg/cmd"
	corecfg "github.com/Axway/agent-sdk/pkg/config"
	"github.com/Axway/agent-sdk/pkg/notify"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/solace-iot-team/solace-axway-agent/pkg/config"
	"github.com/solace-iot-team/solace-axway-agent/pkg/connector"
	"github.com/solace-iot-team/solace-axway-agent/pkg/notification"
	"strings"
)

// RootCmd - Agent root command
var RootCmd cmd.AgentRootCmd
var bootstrappingConifg *config.BootstrappingConfig
var connectorConfig *config.ConnectorConfig
var iCfg *IntegrationtestConfig
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
		executeIntegrationTests,   // Callback for executing the agent
		corecfg.DiscoveryAgent,    // Agent Type (Discovery or Traceability)
	)
}

// Callback that agent will call to process the execution
func run() error {
	//nothing to do

	return nil
}

func executeIntegrationTests() error {
	log.Infof("=== Starting Integration Tests against Connector Server:%s with Org:%s", connectorConfig.ConnectorURL, iCfg.Org)
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

	err = executeTestCRUDApiProduct()
	if err != nil {
		return err
	}
	err = executeTestCRUDApiProduct()
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
	log.Infof("=== DONE Integration Tests against Connector Server:%s with Org:%s", connectorConfig.ConnectorURL, iCfg.Org)
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
	listProducts = append(listProducts, iCfg.ApiProductName)
	var webHooks *connector.SolaceWebhook = nil
	if addWebhook {
		if addTrustedCNs {
			listCNs := strings.Split("*.solace.com,my.company.org", ",")
			webHooks = &connector.SolaceWebhook{
				HttpMethod:               "post",
				CallbackUrl:              "http://does.not.work",
				AuthenticationMethod:     "header",
				AuthenticationSecret:     "secret",
				AuthenticationIdentifier: "identifier",
				InvocationOrder:          "parallel",
				TrusedCNs:                listCNs,
			}
		} else {
			webHooks = &connector.SolaceWebhook{
				HttpMethod:               "post",
				CallbackUrl:              "http://does.not.work",
				AuthenticationMethod:     "header",
				AuthenticationSecret:     "secret",
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
		if env.Name == iCfg.ServiceId {
			foundEnv = true
		}
	}
	if foundEnv {
		log.Tracef("connector.GetOrgConnector().DeleteEnvironment /%/%", iCfg.Org, iCfg.ServiceId)
		success, err := connector.GetOrgConnector().DeleteEnvironment(iCfg.Org, iCfg.ServiceId)
		if err != nil {
			log.Tracef("DeleteEnvironments faulted")
			return err
		}
		if !success {
			log.Tracef("DeleteEnvironment was not HTTP-Code < 300")
			return errors.New("DeleteEnvironment was not HTTP < 300")
		}
		log.Trace("Deleted Environment: %s", iCfg.ServiceId)
	}
	protocolVersions := make([]map[string]string, 0)
	protocolVersion := map[string]string{
		"name":    "mqtt",
		"version": "3.1.1",
	}
	protocolVersions = append(protocolVersions, protocolVersion)
	log.Tracef("connector.GetOrgConnector().CreateEnvironment /%/%", iCfg.Org, iCfg.ServiceId)
	err = connector.GetOrgConnector().CreateEnvironment(iCfg.Org, iCfg.ServiceId, "Integration Test Environment", iCfg.ServiceId, protocolVersions)
	if err != nil {
		log.Tracef("Could not create Environment")
		return err
	}
	log.Tracef("Environment created")
	return nil
}

func executeTestCRUDApiProduct() error {
	log.Tracef("connector.GetOrgConnector().IsAPIProductAvailable /%s/%s", iCfg.Org, iCfg.ApiProductName)
	found, err := connector.GetOrgConnector().IsAPIProductAvailable(iCfg.Org, iCfg.ApiProductName)
	if err != nil {
		log.Tracef("IsAPIProductAvailable faulted")
		return err
	}
	if found {
		log.Tracef("Found ApiProduct: %s", iCfg.ApiProductName)
		log.Tracef("connector.GetOrgConnector().RemoveAPIProduct /%s/%s", iCfg.Org, iCfg.ApiProductName)
		err := connector.GetOrgConnector().RemoveAPIProduct(iCfg.Org, iCfg.ApiProductName, false)
		if err != nil {
			log.Tracef("Could not delete ApiProduct")
			return err
		}
		log.Tracef("ApiProduct: %S deleted", iCfg.ApiName)
	}

	permissions := map[string]string{
		"abc": "efg",
	}
	envNames := make([]string, 0)
	apiNames := make([]string, 0)
	protocols := make([]connector.Protocol, 0)

	envNames = append(envNames, iCfg.ServiceId)
	apiNames = append(apiNames, iCfg.ApiName)
	version := connector.CommonVersion("3.1.1")
	protocols = append(protocols, connector.Protocol{
		Name:    "mqtt",
		Version: &version,
	})
	log.Tracef("connector.GetOrgConnector().PublishAPIProduct /%s/%s", iCfg.Org, iCfg.ApiProductName)
	err = connector.GetOrgConnector().PublishAPIProduct(iCfg.Org, iCfg.ApiProductName, apiNames, envNames, protocols, permissions)
	if err != nil {
		log.Tracef("Could not create APIProduct")
		return err
	}
	log.Tracef("Created APIProduct")
	return nil
}

func executeTestCRUDAPI() error {
	log.Tracef("connector.GetOrgConnector().IsAPIAvailable /%s/%s", iCfg.Org, iCfg.ApiName)
	found, err := connector.GetOrgConnector().IsAPIAvailable(iCfg.Org, iCfg.ApiName)
	if err != nil {
		log.Tracef("IsAPIAvailable faulted")
		return err
	}
	if found {
		log.Tracef("Found API: %s", iCfg.ApiName)
		log.Tracef("connector.GetOrgConnector().RemoveAPI /%s/%s", iCfg.Org, iCfg.ApiName)
		err := connector.GetOrgConnector().RemoveAPI(iCfg.Org, iCfg.ApiName, false)
		if err != nil {
			log.Tracef("Could not delete API")
			return err
		}
		log.Tracef("API: %S deleted", iCfg.ApiName)
	}
	apiSpec, errDecode := base64.StdEncoding.DecodeString(iCfg.ApiSpec)
	if errDecode != nil {
		log.Tracef("Could not base64 decode ApiSpec")
		return errDecode
	}
	log.Tracef("connector.GetOrgConnector().PublishAPI /%s/%s", iCfg.Org, iCfg.ApiName)
	err = connector.GetOrgConnector().PublishAPI(iCfg.Org, iCfg.ApiName, apiSpec)
	if err != nil {
		log.Tracef("Could not publish Api %s", iCfg.ApiName)
		return err
	}
	log.Tracef("API: %s published", iCfg.ApiName)
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

// todo: refactor and move to some util package
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

	// Parse the config from bound properties and setup gateway config
	connectorConfig = &config.ConnectorConfig{
		ConnectorURL:                rootProps.StringPropertyValue("connector.url"),
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
		NotifierHealthMessage:      rootProps.StringPropertyValue("notifier.healthmessage"),
		NotifierURL:                rootProps.StringPropertyValue("notifier.url"),
		NotifierApiConsumerKey:     rootProps.StringPropertyValue("notifier.apiConsumerKey"),
		NotifierApiConsumerSecret:  rootProps.StringPropertyValue("notifier.apiConsumerSecret"),
		NotifierApiAuthType:        rootProps.StringPropertyValue("notifier.apiAuthType"),
		NotifierInsecureSkipVerify: rootProps.BoolPropertyValue("notifier.acceptInsecureCertificates"),
	}

	agentConfig := config.AgentConfig{
		CentralCfg:  centralConfig,
		GatewayCfg:  connectorConfig,
		NotifierCfg: notifierConfig,
	}

	iCfg = &IntegrationtestConfig{
		Org:            rootProps.StringPropertyValue("integrationtest.org"),
		OrgToken:       rootProps.StringPropertyValue("integrationtest.orgToken"),
		ServiceId:      rootProps.StringPropertyValue("integrationtest.serviceId"),
		TeamName:       rootProps.StringPropertyValue("integrationtest.teamName"),
		ApiName:        rootProps.StringPropertyValue("integrationtest.apiName"),
		ApiSpec:        rootProps.StringPropertyValue("integrationtest.apiSpec"),
		ApiProductName: rootProps.StringPropertyValue("integrationtest.apiProductName"),
		TeamAppName:    rootProps.StringPropertyValue("integrationtest.teamAppName"),
		Cleanup:        rootProps.BoolPropertyValue("integrationtest.cleanup"),
	}

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

func GetAgentConfig() *config.ConnectorConfig {
	// GetAgentConfig - Returns the agent config
	return connectorConfig
}
