package cmd

import (
	"fmt"
	"github.com/Axway/agent-sdk/pkg/agent"
	"github.com/Axway/agent-sdk/pkg/apic"
	corecmd "github.com/Axway/agent-sdk/pkg/cmd"
	corecfg "github.com/Axway/agent-sdk/pkg/config"
	"github.com/Axway/agent-sdk/pkg/jobs"
	"github.com/Axway/agent-sdk/pkg/notify"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/sirupsen/logrus"
	"github.com/solace-iot-team/solace-axway-agent/pkg/config"
	"github.com/solace-iot-team/solace-axway-agent/pkg/connector"
	"github.com/solace-iot-team/solace-axway-agent/pkg/gateway"
	"github.com/solace-iot-team/solace-axway-agent/pkg/notification"
	"time"
)

// RootCmd - Agent root command
var RootCmd corecmd.AgentRootCmd
var bootstrappingConifg *config.BootstrappingConfig
var connectorConfig *config.ConnectorConfig
var notifierConfig *config.NotifierConfig

var sendEmail bool = false
var sendNotification bool = false

//called once by go convention
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

func registerSchemaProcessors() {
	if bootstrappingConifg.PublishSubscriptionSchema {
		theJob := SubscriptionSchemaPublisherJob{}
		_, err := jobs.RegisterRetryJob(&theJob, 3)
		if err != nil {
			log.Errorf("Could not register Schema Publisher job", err)
		} else {
			log.Infof("Registered Subscription Schema Publisher")
		}
	}

	if bootstrappingConifg.ProcessSubscriptionSchema {
		theJob2 := SubscriptionSchemaProcessorJob{}
		_, err := jobs.RegisterIntervalJob(&theJob2, 60*time.Second)
		if err != nil {
			log.Errorf("Could not register Subscription Schema Processor job", err)
		} else {
			log.Infof("Registered Subscription Schema Processor")
		}
	}

}

func listenToSubscriptions() error {
	registerSchemaProcessors()
	//log.Info(agent.GetCentralClient().DumpToken())
	log.Infof("======   Configured Solace-Connector URL:%s Axway-Environment:%s", connectorConfig.ConnectorURL, agent.GetCentralConfig().GetEnvironmentName())
	subMan := agent.GetCentralClient().GetSubscriptionManager()
	subMan.RegisterProcessor(apic.SubscriptionApproved, handleApprovedSubscription)
	subMan.RegisterProcessor(apic.SubscriptionUnsubscribeInitiated, handleUnsubscribeSubscription)
	subMan.Start()
	return nil
}

func handleUnsubscribeSubscription(subscription apic.Subscription) {
	log.Tracef(" Handling unsubscribe for [Subscription:%s] ", subscription.GetName())
	container, err := gateway.NewSubscriptionMiddleware(subscription)
	if err != nil {
		log.Errorf("Handling Unsubscribe for [Subscription:%s] was not successful. [%s]", subscription.GetName(), err.Error())
		return
	}
	if subscription.GetRemoteAPIID() == "" {
		err := container.ProcessUnsubscribeSubscription()
		if err != nil {
			log.Error(err)
			//TODO add some debug context-id to find log message
			if sendNotification {
				log.Tracef("publishing unsubscribe failed notification")
				container.NotifyFailure("unsubscribe", "Failed to de-provision api", "undefined")
			}
			subscription.UpdateState(apic.SubscriptionFailedToUnsubscribe, "Failed to de-provision AsyncAPI")

		} else {
			if sendNotification {
				log.Tracef("publishing unsubscribe success notification")
				container.NotifySuccess("unsubscribe", "de-provisioned api", "undefined")
			}
			if sendEmail {
				sendEmailUnsubscribe(container)
			}
			subscription.UpdateState(apic.SubscriptionUnsubscribed, "AsyncAPI de-provisioned at PubSub+ Broker")
		}
	}

}

func handleApprovedSubscription(subscription apic.Subscription) {
	log.Tracef(" Handling subscribe for [Subscription:%s] ", subscription.GetName())
	container, err := gateway.NewSubscriptionMiddleware(subscription)
	if err != nil {
		log.Errorf("Handling subscribe for [Subscription:%s] was not successful. [%s]", subscription.GetName(), err.Error())
		return
	}

	if subscription.GetRemoteAPIID() == "" {
		validSubscription, feedback := validateSolaceCallbackSubscription(subscription)
		if !validSubscription {
			log.Infof("Rejected subscription (%s) and set to FAILED STATE. Validation of Solace Callback failed: %s", subscription.GetName(), feedback)
			subscription.UpdateState(apic.SubscriptionFailedToSubscribe, fmt.Sprintf("Could not process subscription: %s", feedback))
			return
		}
		err := container.ProcessSubscription()
		if err != nil {
			log.Error(err)
			//TODO add some debug context-id to find log message
			if sendNotification {
				log.Tracef("publishing subscribe failed notification")
				container.NotifyFailure("subscribe", "Failed to provision api", "undefined")
			}
			subscription.UpdateState(apic.SubscriptionFailedToSubscribe, "Failed to provision AsyncAPI")
		} else {
			if sendNotification {
				log.Tracef("publishing subscribe success notification")
				container.NotifySuccess("subscribe", "provisioned api", "undefined")
			}
			if sendEmail {
				sendEmailSubscribe(container)
			}
			subscription.UpdateState(apic.SubscriptionActive, "AsyncAPI provisioned to PubSub+ Broker")
		}
	}
}

func sendEmailSubscribe(container *gateway.SubscriptionMiddleware) error {
	url := agent.GetCentralConfig().GetURL() + "/catalog/explore/" + container.AxSub.GetSubscriptionCatalogItemId()
	message := notify.NewSubscriptionNotification(container.AxSub.GetSubscriberEmailAddress(), "message ignored ", apic.SubscriptionActive)
	message.SetCatalogItemInfo(container.AxSub.GetSubscriptionCatalogItemId(), container.AxSub.GetCatalogItemName(), url)
	message.SetOauthInfo(container.AxSub.GetSubscriptionCredentials().ConsumerKey, DerefString(container.AxSub.GetSubscriptionCredentials().ConsumerSecret))
	message.SetAuthorizationTemplate("oauth")
	message.ApiManagerId = container.AxSub.GetSolaceAsyncApiAppInternalId()
	err := message.NotifySubscriber(container.AxSub.GetSubscriberEmailAddress())
	if err != nil {
		log.Errorf("Notification of SUBSCRIBE event by Email failed", err)
		return err
	} else {
		log.Tracef("Informed %s by Email to %s about subscription", container.AxSub.GetSubscriberUserName(), container.AxSub.GetSubscriberEmailAddress())
		return nil
	}
}

func sendEmailUnsubscribe(container *gateway.SubscriptionMiddleware) error {
	url := agent.GetCentralConfig().GetURL() + "/catalog/explore/" + container.AxSub.GetSubscriptionCatalogItemId()
	message := notify.NewSubscriptionNotification(container.AxSub.GetSubscriberEmailAddress(), "message ignored ", apic.SubscriptionUnsubscribed)
	message.SetCatalogItemInfo(container.AxSub.GetSubscriptionCatalogItemId(), container.AxSub.GetCatalogItemName(), url)
	err := message.NotifySubscriber(container.AxSub.GetSubscriberUserName())
	if err != nil {
		log.Errorf("Notification of UNSUBSCRIBE event by Email failed", err)
		return err
	} else {
		log.Tracef("Informed %s by Email to %s about unsubscribe", container.AxSub.GetSubscriberUserName(), container.AxSub.GetSubscriberEmailAddress())
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
