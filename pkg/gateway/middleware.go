package gateway

import (
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	"github.com/solace-iot-team/agent-sdk/pkg/agent"
	"github.com/solace-iot-team/agent-sdk/pkg/apic"
	"github.com/solace-iot-team/agent-sdk/pkg/apic/apiserver/models/management/v1alpha1"
	"github.com/solace-iot-team/agent-sdk/pkg/util/log"
	"github.com/solace-iot-team/solace-axway-agent/pkg/connector"
	"sort"
)

// SubscriptionContainer - holds additional information for a subscription
type SubscriptionContainer struct {
	Valid bool
	Sub apic.Subscription
	Service *v1alpha1.APIService
	ServiceInstance *v1alpha1.APIServiceInstance
	ServiceRevision *v1alpha1.APIServiceRevision

}

// NewSubscriptionContainer - creates new SubscriptionContainer
func NewSubscriptionContainer(subscription apic.Subscription) (*SubscriptionContainer, error) {
	service,err := agent.GetCentralClient().GetAPIServiceByName(subscription.GetAPIServiceName())
	if err !=nil {return nil,err}
	serviceinstance,err := agent.GetCentralClient().GetAPIServiceInstanceByName(subscription.GetAPIServiceInstanceName())
	if err !=nil {return nil,err}
	servicerevision,err := agent.GetCentralClient().GetAPIRevisionByName(subscription.GetAPIServiceRevisionName())
	if err !=nil {return nil,err}

	container := SubscriptionContainer{
		Sub: subscription,
		Service: service,
		ServiceInstance: serviceinstance,
		ServiceRevision: servicerevision,
	}
	if (service.Metadata.ID=="" || serviceinstance.Metadata.ID=="" || servicerevision.Metadata.ID==""){
		container.Valid = false
	} else {
		container.Valid = true
	}
	return &container,nil
}

// DumpDebug - Dumps debug information
func (container *SubscriptionContainer) DumpDebug() string {
	dump := "[ SubscriptionContainer [Subscription:"+container.Sub.GetName()+"]"
	if !container.Valid{
		dump = dump+" [Valid:FALSE] ]"
		return dump
	}
	dump = dump+" [Valid:TRUE]"
	dump = dump+fmt.Sprintf(" [IsEnvironmentDefined:%v]",container.IsEnvironmentDefined())
	dump = dump+fmt.Sprintf(" [IsExternalAPIIDDefined:%v]",container.IsExternalAPIIDDefined())
	dump = dump+fmt.Sprintf(" [IsExternalAPINameDefined:%v]",container.IsExternalAPINameDefined())
	dump = dump+fmt.Sprintf(" [Environment:%s]",container.GetEnvironmentName())
	dump = dump+fmt.Sprintf(" [RevisionName:%s]",container.GetRevisionName())
	dump = dump+fmt.Sprintf(" [ExternalAPIID:%s]",container.GetExternalAPIName())
	dump = dump+fmt.Sprintf(" [ExternalAPIName:%s]",container.GetExternalAPIName())
	dump = dump+" ]"
	return dump
}

// Debug - dumps debug information
func (container *SubscriptionContainer) Debug() string {
	dump := "[Attributes "
	service,err := agent.GetCentralClient().GetAPIServiceByName(container.Sub.GetAPIServiceName())
	if err != nil {
		log.Error("Did not work out",err)
		return "Error"
	}
	for k,v := range service.Attributes {
		dump = dump + fmt.Sprintf("[%s:%s]",k,v)
	}
	dump = dump + " ]"
	return dump
}

// ProcessUnsubscribeSubscription - Orchestrates entire unsubscription steps
func (container *SubscriptionContainer) ProcessUnsubscribeSubscription() error {
	//todo prepare verbose debug-message and remove code duplications
	log.Debugf("[BEGIN] [MIDDLEWARE.ProcessUnsubscribeSubscription] [Environment:%s] [Revision/API:%s][", container.GetEnvironmentName(), container.GetRevisionName())
	check, err := container.IsEnvironmentAsOrgAvailable()
	if err != nil {
		log.Error("[ERROR] [Step X] [IsEnvironmentAsOrgAvailable] ", err)
		return err
	}
	if !check {
		log.Warn("[ABORTING PROCESSING] [Step X]  [IsEnvironmentAsOrgAvailable] [Organization missing in Connector]", container.GetEnvironmentName())
		return errors.New("Organization missing in Connector:" + container.GetEnvironmentName())
	}
	//TODO remove dummy
	//check,err = container.GetDummySuccessOrFault(false)
	check, err = container.IsTeamAppAvailable()
	if err != nil {
		log.Error("[ERROR] [Step X] [IsTeamAppAvailable]", err)
		return err
	}
	if check {
		err = container.RemoveTeamApp()
		if err != nil {
			log.Error("[ERROR] [Step x] [RemoveTeamApp]", err)
			return err
		}
	} else {
		log.Warn("[WARNING] [Step x] [IsTeamAppAvailable] [No Team App found]")
	}

	check, err = container.IsAPIProductAvailable()
	if err != nil {
		log.Error("[ERROR] [Step X] [IsAPIProductAvailable]", err)
		return err
	}
	if (check){
		//try to remove API Product
		err = container.RemoveAPIProduct(true)
		if err != nil {
			log.Error("[ERROR] [Step x] [RemoveAPIProduct]", err)
			return err
		}
	} else {
		log.Warn("[WARNING] [Step x] [IsAPIProductAvailable] [No Product found]")
	}

	check, err = container.IsConnectorAPIAvailable()
	if err != nil {
		log.Error("[ERROR] [Step X] [IsConnectorAPIAvailable]", err)
		return err
	}
	if check {
		err = container.RemoveAPI(true)
		if err != nil {
			log.Error("[ERROR] [Step x] [RemoveAPI]", err)
			return err
		}
	} else {
		log.Warn("[WARNING] [Step x] [IsConnectorAPIAvailable] [No API found]")
	}
	return nil
}

// ProcessSubscription  - Orchestrates entire subscription steps
func (container *SubscriptionContainer) ProcessSubscription() error {
	//todo prepare verbose debug-message and remove code duplications
	log.Debugf("[BEGIN] [MIDDLEWARE.ProcessSubscription] [Environment:%s] [Revision/API:%s][",container.GetEnvironmentName(), container.GetRevisionName())
	provisionedAPI := false
	provisionedAPIProduct := false
	provisionedTeam := false
	provisionedTeamApp := false

	check, err := container.IsEnvironmentAsOrgAvailable()
	if err != nil {
		log.Error("[ERROR] [Step 1] [IsEnvironmentAsOrgAvailable] ", err)
		return err
	}
	if !check {
		log.Warn("[ABORTING PROCESSING] [Step 1]  [IsEnvironmentAsOrgAvailable] [Organization missing in Connector]",container.GetEnvironmentName() )
		return errors.New("Organization missing in Connector:"+container.GetEnvironmentName())
	}
	//Environment / Organization exist in Connector
	check, err = container.IsConnectorAPIAvailable()
	if err != nil {
		log.Error("[ERROR] [Step 2] [IsConnectorAPIAvailable]")
		return err
	}
	if !check {
		err := container.PublishAPI()
		if err != nil {
			log.Error("[ERROR] [Step 3] [PublishAPI]",err)
			return err
		}
		log.Info("[OK] [Step 3] [PublishAPI] [API Published]")
		provisionedAPI = true

	}
	//API got published or already existed

	check,err = container.IsAPIProductAvailable()
	if err != nil {
		log.Error("[ERROR] [Step 4] [IsAPIProductAvailable]", err)
		return err
	}
	if !check {
		err := container.PublishAPIProduct()
		if err != nil {
			log.Error("[ERROR] [Step 5] [PublishAPIProduct] [API-Product not provisioned]")
			return err
		}
		provisionedAPIProduct = true
  		log.Info("[OK] [Step 5] [PublishAPIProduct] [API-Product provisioned]")
	}

	check,err = container.IsConnectorTeamAvailable()
	if err != nil {
		log.Error("[ERROR] [Step 6] [IsConnectorTeamAvailable]", err)
		return err
	}
	if !check {
		err := container.PublishTeam()
		if err != nil {
			log.Error("[ERROR] [Step 7] [PublishTeam] [Team not provisioned]")
			return err
		}
		provisionedTeam = true
		log.Info("[OK] [Step 7] [PublishTeam] [Team provisioned]")
	}

	//TODO remove dummy
	//check,err = container.GetDummySuccessOrFault(false)
	check,err = container.IsTeamAppAvailable()
	if err != nil {
		log.Error("[ERROR] [Step 8] [IsTeamAppAvailable]", err)
		return err
	}
	if !check {
		credentials,err := container.PublishTeamApp()
		if err != nil {
			log.Error("[ERROR] [Step 9] [PublishTeamApp] [TeamApp not provisioned]")
			return err
		}
		provisionedTeamApp = true
		log.Info("[OK] [Step 9] [PublishTeamApp] [Team provisioned]")
		//TODO remove before going to production
		log.Info("[OK] [Step 9] [PublishTeamApp] [Credentials] [Key:%s] [Secret:%s]",credentials.Secret.ConsumerKey, credentials.Secret.ConsumerKey)
	}

	if (provisionedAPI || provisionedAPIProduct || provisionedTeam || provisionedTeamApp){
		log.Debugf("[END] [MIDDLEWARE.ProcessSubscription] [API-Provisioned:%t] [API-Product-Provisioned:%t] [API-Provisioned:%t] [Team-Provisioned:%t] [Team-App-Provisioned:%t] [Environment:%s] [Revision/API:%s] [Team:%s] [TeamApp:%s]", provisionedAPI, provisionedAPIProduct, provisionedTeam,provisionedTeamApp,container.GetEnvironmentName(), container.GetRevisionName(),container.Sub.GetOwningTeamId(), container.Sub.GetID())

	} else {
		log.Debugf("[END] [NOTHING TO DO] [MIDDLEWARE.ProcessSubscription] [API- and API-Product already existed - nothing to do] [Environment:%s] [Revision/API:%s] [Team:%s] [Team-App:%s]", container.GetEnvironmentName(), container.GetRevisionName(), container.Sub.GetOwningTeamId(), container.Sub.GetID())
	}
	return nil

}

// GetDummySuccessOrFault -for development only
func (container *SubscriptionContainer) GetDummySuccessOrFault(success bool) (bool,error) {
	return success,nil
}

// GetRevisionName - Facade to retrieve RevisionName
func (container *SubscriptionContainer) GetRevisionName() string {
	return  container.ServiceRevision.GetName()
}

// IsEnvironmentDefined - Facade to check if environment is set in Service Instance
func (container *SubscriptionContainer) IsEnvironmentDefined() bool {
	return  container.ServiceInstance.Metadata.Scope.Name != ""
}

// GetEnvironmentName - Facade to get environment name (Service Instance Scope Name)
func (container *SubscriptionContainer) GetEnvironmentName() string {
	return  container.ServiceInstance.Metadata.Scope.Name
}

// IsExternalAPIIDDefined - Facade to check if External API ID is set
func (container *SubscriptionContainer) IsExternalAPIIDDefined() bool {
	return  container.GetExternalAPIID()!=""
}

// IsExternalAPINameDefined - Facade to check if External API Name is set
func (container *SubscriptionContainer) IsExternalAPINameDefined() bool {
	return  container.GetExternalAPIName()!=""
}

// GetExternalAPIID - Facade to get External API ID
func (container *SubscriptionContainer) GetExternalAPIID() string {
	return  container.ServiceRevision.GetAttributes()["externalAPIID"]
}

// GetExternalAPIName - Facade to get External API Name
func (container *SubscriptionContainer) GetExternalAPIName() string {
	return  container.ServiceRevision.GetAttributes()["externalAPIName"]
}

// GetAPISpec - Facade ti get API Spec (AsyncAPI spec)
func (container *SubscriptionContainer) GetAPISpec() string {
	return  container.ServiceRevision.Spec.Definition.Value
}

//IsEnvironmentAsOrgAvailable - Facade to check in Connector if an organization exists that has the same name as Axway Environment of the subscription
func (container *SubscriptionContainer) IsEnvironmentAsOrgAvailable() (bool,error) {
	if (container.GetEnvironmentName()==""){
		return false,nil
	}
	return connector.GetAdminConnector().IsOrgRegistered(container.GetEnvironmentName())
}

//IsConnectorAPIAvailable - Facade to check via Connector if API already exists
func (container *SubscriptionContainer) IsConnectorAPIAvailable() (bool,error) {
	return connector.GetOrgConnector().IsAPIAvailable(container.GetEnvironmentName(), container.GetRevisionName())
}

//IsAPIProductAvailable - Facade to check via Connector if API-Product exists
func (container *SubscriptionContainer) IsAPIProductAvailable() (bool,error) {
	//by convention api and product have same name: revisionName
	return connector.GetOrgConnector().IsAPIProductAvailable(container.GetEnvironmentName(), container.GetRevisionName())
}

//IsConnectorTeamAvailable - Facade to check via Connector if Team exists
func (container *SubscriptionContainer) IsConnectorTeamAvailable() (bool,error) {
	return connector.GetOrgConnector().IsTeamAvailable(container.GetEnvironmentName(), container.Sub.GetOwningTeamId())
}

//IsTeamAppAvailable - Facade to check via Connector if Team Application exists
func (container *SubscriptionContainer) IsTeamAppAvailable() (bool,error) {
	return connector.GetOrgConnector().IsTeamAppAvailable(container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.Sub.GetID())
}

//PublishAPIProduct - Facade to publish via Connector an API Product (idempotent)
func (container *SubscriptionContainer) PublishAPIProduct() error {
	//todo cross-check all environments will share same protocols
	connectorEnvs,err := connector.GetOrgConnector().GetListEnvironments(container.GetEnvironmentName())
	if err != nil {
		return err
	}
	if len(connectorEnvs) == 0 {
		log.Warnf("[PublishAPIProduct] [There are no Environments provisioned in Connector for the organization] [Org:%s]",container.GetEnvironmentName())
	}
	envNames := make([]string,0)
	protocols := make([] connector.Protocol,0)
	permissions := container.Service.GetAttributes()
	for _, endpoint := range container.ServiceInstance.Spec.Endpoint {

		idx := sort.Search(len(connectorEnvs), func(i int) bool {
			return endpoint.Host == connectorEnvs[i].Host
		})
		if (idx<len(connectorEnvs) && connectorEnvs[idx].Host==endpoint.Host){
			envNames = append(envNames, connectorEnvs[idx].Name)
			protocolVersion,found := connectorEnvs[idx].ProtocolVersion[endpoint.Protocol]
			if (found){
				protocols = append(protocols,connector.Protocol{Name: connector.ProtocolName(endpoint.Protocol), Version: &protocolVersion})
			} else {
				//todo detailed error message
				return errors.New("Protocol/Version not in Environment")
			}
		} else {
			return errors.New("Environment not found")
		}
	}

	return connector.GetOrgConnector().PublishAPIProduct(container.GetEnvironmentName(), container.GetRevisionName(),[]string{container.GetRevisionName()},envNames,protocols, permissions)
}

//RemoveAPI - Facade to remove via connector an API
func (container *SubscriptionContainer) RemoveAPI(ignoreConflict bool) error {
	return connector.GetOrgConnector().RemoveAPI(container.GetEnvironmentName(),container.GetRevisionName(), ignoreConflict)
}

//RemoveAPIProduct - Facade to remove via Connector an API Product
func (container *SubscriptionContainer) RemoveAPIProduct(ignoreConflict bool) error {
	return connector.GetOrgConnector().RemoveAPIProduct(container.GetEnvironmentName(), container.GetRevisionName(), ignoreConflict)
}

//RemoveTeamApp - Facade to remove via Connector a Team Application
func (container *SubscriptionContainer) RemoveTeamApp() error {
	apiProducts := make([]string,0)
	apiProducts = append(apiProducts, container.GetRevisionName())
	return connector.GetOrgConnector().RemoveTeamApp(container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.Sub.GetID())
}

//PublishTeamApp - Facade to publish via Connector a Team Application
func (container *SubscriptionContainer) PublishTeamApp() (*connector.Credentials,error) {
	apiProducts := make([]string,0)
	apiProducts = append(apiProducts, container.GetRevisionName())
	return connector.GetOrgConnector().PublishTeamApp(container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.Sub.GetID(), "Created by Axway-Agent", apiProducts)
}

//PublishAPI - Facade to publish via Connector an API
func (container *SubscriptionContainer) PublishAPI() error {
	decodedAPISpec,err := base64.StdEncoding.DecodeString(container.GetAPISpec())
	if err != nil {
		return err
	}
	return connector.GetOrgConnector().PublishAPI(container.GetEnvironmentName(),container.GetRevisionName(), decodedAPISpec)
}

//PublishTeam - Facade to publish via Connector a Team
func (container *SubscriptionContainer) PublishTeam() error {
	return connector.GetOrgConnector().PublishTeam(container.GetEnvironmentName(),container.Sub.GetOwningTeamId())
}
