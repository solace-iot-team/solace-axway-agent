package integrationtest

import (
	"errors"
	corecfg "github.com/Axway/agent-sdk/pkg/config"
	"github.com/Axway/agent-sdk/pkg/notify"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/sirupsen/logrus"
	"github.com/solace-iot-team/solace-axway-agent/pkg/config"
	"github.com/solace-iot-team/solace-axway-agent/pkg/connector"
	"github.com/solace-iot-team/solace-axway-agent/pkg/notification"
)

// RootCmd - Agent root command
var RootCmd ConnectorIntegrationTestCmd
var connectorConfig *config.ConnectorConfig
var integrationtestConfig *IntegrationtestConfig
var notifierConfig *config.NotifierConfig

var sendEmail bool = false
var sendNotification bool = false

func init() {
	log.SetLevel(logrus.TraceLevel)
	// Create new root command with callbacks to initialize the agent config and command execution.
	// The first parameter identifies the name of the yaml file that agent will look for to load the config
	RootCmd = NewRootCmd(
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
	healthCheck, err := connector.GetOrgConnector().IsHealthCheck()
	if err != nil {
		log.Tracef("Health Check of Connector throws Error")
		return err
	}
	if !healthCheck {
		return errors.New("Health Check of Connector was not successfull")
	}
	log.Infof("Health Check of Connector was successfull")

	found, err := connector.GetOrgConnector().IsOrgRegistered(integrationtestConfig.Org)
	if err != nil {
		log.Tracef("IsOrgRegistered faulted")
		return err
	}
	if found {
		log.Tracef("Found Org:%s and try to delete it", integrationtestConfig.Org)
		ok, err := connector.GetOrgConnector().DeleteOrg(integrationtestConfig.Org)
		if err != nil {
			log.Tracef("Deleting Org throws Error")
			return err
		}
		if !ok {
			log.Tracef("Could not delete Org")
			return errors.New("Could not create Org")
		}
		log.Tracef("Org %s deleted", integrationtestConfig.Org)
	} else {
		log.Infof("Could not find org:%s", integrationtestConfig.Org)
	}
	orgToken := integrationtestConfig.OrgToken
	test := make([]interface{}, 1)
	test[0] = orgToken
	ok, err := connector.GetOrgConnector().CreateOrg(integrationtestConfig.Org, &test[0])
	if err != nil {
		log.Tracef("Creating Org throws Error")
		return err
	}
	if !ok {
		log.Tracef("Could not create Org")
		return errors.New("Could not create Org")
	}
	log.Tracef("Org %s created", integrationtestConfig.Org)
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
	// Parse the config from bound properties and setup gateway config
	connectorConfig = &config.ConnectorConfig{
		ConnectorURL:                rootProps.StringPropertyValue("connector.url"),
		ConnectorAdminUser:          rootProps.StringPropertyValue("connector.adminUser"),
		ConnectorAdminPassword:      rootProps.StringPropertyValue("connector.adminPassword"),
		ConnectorOrgUser:            rootProps.StringPropertyValue("connector.orgUser"),
		ConnectorOrgPassword:        rootProps.StringPropertyValue("connector.orgPassword"),
		ConnectorInsecureSkipVerify: rootProps.BoolPropertyValue("connector.acceptInsecureCertificates"),
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

	integrationtestConfig = &IntegrationtestConfig{
		Org:      rootProps.StringPropertyValue("integrationtest.org"),
		OrgToken: rootProps.StringPropertyValue("integrationtest.orgToken"),
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
