package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/solace-iot-team/agent-sdk/pkg/agent"
	"github.com/solace-iot-team/agent-sdk/pkg/apic"
	corecmd "github.com/solace-iot-team/agent-sdk/pkg/cmd"
	corecfg "github.com/solace-iot-team/agent-sdk/pkg/config"
	"github.com/solace-iot-team/agent-sdk/pkg/util/log"
	"github.com/solace-iot-team/solace-axway-agent/pkg/config"
	"github.com/solace-iot-team/solace-axway-agent/pkg/connector"
	"github.com/solace-iot-team/solace-axway-agent/pkg/gateway"
)

// RootCmd - Agent root command
var RootCmd corecmd.AgentRootCmd
var gatewayConfig *config.GatewayConfig

func init() {
	log.SetLevel(logrus.TraceLevel)
	// Create new root command with callbacks to initialize the agent config and command execution.
	// The first parameter identifies the name of the yaml file that agent will look for to load the config
	RootCmd = corecmd.NewRootCmd(
		"solace_axway_agent",   // Name of the yaml file
		"Solace Axway Agent", // Agent description
		initConfig,               // Callback for initializing the agent config
		listenToSubscriptions,    // Callback for executing the agent
		corecfg.DiscoveryAgent,   // Agent Type (Discovery or Traceability)
	)
}

// Callback that agent will call to process the execution
func run() error {
	//nothing to do
	return nil
}

func listenToSubscriptions() error {
	err:= connector.Initialize(gatewayConfig)
	if err != nil {
		panic(err)
	}
	//log.Info(agent.GetCentralClient().DumpToken())
	subMan := agent.GetCentralClient().GetSubscriptionManager()
	subMan.RegisterProcessor(apic.SubscriptionApproved, handleApprovedSubscription)
	subMan.RegisterProcessor(apic.SubscriptionUnsubscribeInitiated, handleUnsubscribeSubscription)
	subMan.Start()
	return nil
}

func handleUnsubscribeSubscription(subscription apic.Subscription) {
	log.Debugf(" Handling unsubscribe for [Subscription:%s] ",subscription.GetName())
	container, err := gateway.NewSubscriptionContainer(subscription)
	if err != nil {
		log.Errorf("Handling Unsubscribe for [Subscription:%s] was not successful. [%s]",subscription.GetName(),err.Error())
		return
	}
	if (subscription.GetRemoteAPIID()=="" && container.Valid){
		//log.Info(" DUMP: ",container.Debug())
		err := container.ProcessUnsubscribeSubscription()
		if err != nil {
			log.Error(err)
			//TODO add some debug context-id to find log message
			subscription.UpdateState(apic.SubscriptionFailedToUnsubscribe,"Failed to de-provision AsyncAPI")
		} else {
			subscription.UpdateState(apic.SubscriptionUnsubscribed,"AsyncAPI de-provisioned at PubSub+ Broker")
		}
	}

}

func handleApprovedSubscription(subscription apic.Subscription) {
	log.Debugf(" Handling subscribe for [Subscription:%s] ",subscription.GetName())
	container, err := gateway.NewSubscriptionContainer(subscription)
	if err != nil {
		log.Errorf("Handling subscribe for [Subscription:%s] was not successful. [%s]",subscription.GetName(),err.Error())
		return
	}
	if (subscription.GetRemoteAPIID()=="" && container.Valid){
		//log.Info(" DUMP: ",container.Debug())
		err := container.ProcessSubscription()
		if err != nil {
			log.Error(err)
			//TODO add some debug context-id to find log message
			subscription.UpdateState(apic.SubscriptionFailedToSubscribe,"Failed to provision AsyncAPI")
		} else {
			subscription.UpdateState(apic.SubscriptionActive,"AsyncAPI provisioned to PubSub+ Broker")
		}
	}
}

// Callback that agent will call to initialize the config. CentralConfig is parsed by Agent SDK
// and passed to the callback allowing the agent code to access the central config
func initConfig(centralConfig corecfg.CentralConfig) (interface{}, error) {
	rootProps := RootCmd.GetProperties()
	// Parse the config from bound properties and setup gateway config
	gatewayConfig = &config.GatewayConfig{
		ConnectorURL:           rootProps.StringPropertyValue("gateway-section.connector_url"),
		ConnectorAdminUser:     rootProps.StringPropertyValue("gateway-section.connector_admin_user"),
		ConnectorAdminPassword: rootProps.StringPropertyValue("gateway-section.connector_admin_password"),
		ConnectorOrgUser:       rootProps.StringPropertyValue("gateway-section.connector_org_user"),
		ConnectorOrgPassword:   rootProps.StringPropertyValue("gateway-section.connector_org_password"),
	}

	agentConfig := config.AgentConfig{
		CentralCfg: centralConfig,
		GatewayCfg: gatewayConfig,
	}
	return agentConfig, nil
}

// GetAgentConfig - Returns the agent config
func GetAgentConfig() *config.GatewayConfig {
	return gatewayConfig
}
