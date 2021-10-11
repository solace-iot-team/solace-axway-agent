package cmd

import (
	"github.com/Axway/agent-sdk/pkg/agent"
	"github.com/Axway/agent-sdk/pkg/apic"
	corecmd "github.com/Axway/agent-sdk/pkg/cmd"
	corecfg "github.com/Axway/agent-sdk/pkg/config"
	"github.com/Axway/agent-sdk/pkg/notify"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/sirupsen/logrus"
	"github.com/solace-iot-team/solace-axway-agent/pkg/config"
	"github.com/solace-iot-team/solace-axway-agent/pkg/connector"
	"github.com/solace-iot-team/solace-axway-agent/pkg/gateway"
	"github.com/solace-iot-team/solace-axway-agent/pkg/notification"
)

// RootCmd - Agent root command
var RootCmd corecmd.AgentRootCmd
var connectorConfig *config.ConnectorConfig
var notifierConfig *config.NotifierConfig

func init() {
	log.SetLevel(logrus.TraceLevel)
	// Create new root command with callbacks to initialize the agent config and command execution.
	// The first parameter identifies the name of the yaml file that agent will look for to load the config
	RootCmd = corecmd.NewRootCmd(
		"solace_axway_agent",   // Name of the yaml file
		"Solace Axway Agent",   // Agent description
		initConfig,             // Callback for initializing the agent config
		listenToSubscriptions,  // Callback for executing the agent
		corecfg.DiscoveryAgent, // Agent Type (Discovery or Traceability)
	)
}

// Callback that agent will call to process the execution
func run() error {
	//nothing to do

	return nil
}

func listenToSubscriptions() error {

	err := connector.Initialize(connectorConfig)
	if err != nil {
		panic(err)
	}
	errNotification := notification.Initialize(notifierConfig)
	if errNotification != nil {
		panic(errNotification)
	}

	//log.Info(agent.GetCentralClient().DumpToken())
	subMan := agent.GetCentralClient().GetSubscriptionManager()

	subMan.RegisterProcessor(apic.SubscriptionApproved, handleApprovedSubscription)
	subMan.RegisterProcessor(apic.SubscriptionUnsubscribeInitiated, handleUnsubscribeSubscription)
	subMan.Start()
	return nil
}

func handleUnsubscribeSubscription(subscription apic.Subscription) {
	log.Debugf(" Handling unsubscribe for [Subscription:%s] ", subscription.GetName())
	container, err := gateway.NewSubscriptionContainer(subscription)
	if err != nil {
		log.Errorf("Handling Unsubscribe for [Subscription:%s] was not successful. [%s]", subscription.GetName(), err.Error())
		return
	}
	if subscription.GetRemoteAPIID() == "" && container.Valid {
		err := container.ProcessUnsubscribeSubscription()
		if err != nil {
			log.Error(err)
			//TODO add some debug context-id to find log message
			container.NotifyFailure("unsubscribe", "Failed to de-provision api", "undefined")
			subscription.UpdateState(apic.SubscriptionFailedToUnsubscribe, "Failed to de-provision AsyncAPI")

		} else {
			container.NotifySuccess("unsubscribe", "de-provisioned api", "undefined")
			sendEmailUnsubscribe(container)
			subscription.UpdateState(apic.SubscriptionUnsubscribed, "AsyncAPI de-provisioned at PubSub+ Broker")
		}
	}

}

func handleApprovedSubscription(subscription apic.Subscription) {
	log.Debugf(" Handling subscribe for [Subscription:%s] ", subscription.GetName())
	container, err := gateway.NewSubscriptionContainer(subscription)
	if err != nil {
		log.Errorf("Handling subscribe for [Subscription:%s] was not successful. [%s]", subscription.GetName(), err.Error())
		return
	}

	if subscription.GetRemoteAPIID() == "" && container.Valid {
		//log.Info(" DUMP: ",container.Debug())
		apicid := subscription.GetApicID()
		log.Infof("APIC-ID: %s", apicid)
		err := container.ProcessSubscription()
		if err != nil {
			log.Error(err)
			//TODO add some debug context-id to find log message
			container.NotifyFailure("subscribe", "Failed to provision api", "undefined")
			subscription.UpdateState(apic.SubscriptionFailedToSubscribe, "Failed to provision AsyncAPI")
		} else {
			container.NotifySuccess("subscribe", "provisioned api", "undefined")
			sendEmailSubscribe(container)
			subscription.UpdateState(apic.SubscriptionActive, "AsyncAPI provisioned to PubSub+ Broker")
		}
	}
}

func sendEmailSubscribe(container *gateway.SubscriptionContainer) error {
	url := agent.GetCentralConfig().GetURL() + "/catalog/explore/" + container.Sub.GetCatalogItemID()
	message := notify.NewSubscriptionNotification(container.SubscriberEmailAddress, "message ignored ", apic.SubscriptionActive)
	message.SetCatalogItemInfo(container.Sub.GetCatalogItemID(), container.CatalogItemName, url)
	message.SetOauthInfo(container.SubscriptionCredentials.ConsumerKey, DerefString(container.SubscriptionCredentials.ConsumerSecret))
	message.SetAuthorizationTemplate("oauth")
	err := message.NotifySubscriber(container.SubscriberEmailAddress)
	if err != nil {
		log.Errorf("Notification of SUBSCRIBE event by Email failed", err)
		return err
	} else {
		log.Infof("Informed %s by Email to %s about subscription", container.SubscriberUserName, container.SubscriberEmailAddress)
		return nil
	}
}

func sendEmailUnsubscribe(container *gateway.SubscriptionContainer) error {
	url := agent.GetCentralConfig().GetURL() + "/catalog/explore/" + container.Sub.GetCatalogItemID()
	message := notify.NewSubscriptionNotification(container.SubscriberEmailAddress, "message ignored ", apic.SubscriptionUnsubscribed)
	message.SetCatalogItemInfo(container.Sub.GetCatalogItemID(), container.CatalogItemName, url)
	err := message.NotifySubscriber(container.SubscriberEmailAddress)
	if err != nil {
		log.Errorf("Notification of UNSUBSCRIBE event by Email failed", err)
		return err
	} else {
		log.Infof("Informed %s by Email to %s about unsubscribe", container.SubscriberUserName, container.SubscriberEmailAddress)
		return nil
	}
}

// todo: refactor and move to some util package
func DerefString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func createSubscriptionSchema() error {
	//log.Infof("TOKEN: %s", agent.GetCentralClient().DumpToken())
	return apic.NewSubscriptionSchemaBuilder(agent.GetCentralClient()).
		SetName("sol-schema-develop-2").
		AddProperty(apic.NewSubscriptionSchemaPropertyBuilder().
			SetName("Callback").
			IsString().
			SetEnumValues([]string{"http://mycallback.com", "http://anothercallback.com", "http://someothecallback.com"}).
			AddEnumValue("Pick a callback").
			SetSortEnumValues().
			SetDescription("Callback of this AsyncAPI v1").
			SetRequired()).
		Update(true).
		AddUniqueKey("8a2d851a7aa166a7017aae28d0af4538").
		Register()

}

// Callback that agent will call to initialize the config. CentralConfig is parsed by Agent SDK
// and passed to the callback allowing the agent code to access the central config
func initConfig(centralConfig corecfg.CentralConfig) (interface{}, error) {
	//configure SMTP notifications
	notify.SetSubscriptionConfig(centralConfig.GetSubscriptionConfig())

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
	return agentConfig, nil
}

// GetAgentConfig - Returns the agent config
func GetAgentConfig() *config.ConnectorConfig {
	return connectorConfig
}
