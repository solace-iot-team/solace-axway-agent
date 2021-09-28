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
	"github.com/solace-iot-team/solace-axway-agent/pkg/notification"
	"sort"
)

// SubscriptionContainer - holds additional information for a subscription
type SubscriptionContainer struct {
	// ConceptMapping
	// Environment.LogicalName - Org
	// Subscription.OwningTeamId - Team
	// ServiceRevision.Name - APIProduct (Name)
	// Subscription.Id - Application (Name)
	// ServiceRevision.Name - API (Name)
	Valid           bool
	Sub             apic.Subscription
	Service         *v1alpha1.APIService
	ServiceInstance *v1alpha1.APIServiceInstance
	ServiceRevision *v1alpha1.APIServiceRevision
}

// NewSubscriptionContainer - creates new SubscriptionContainer
func NewSubscriptionContainer(subscription apic.Subscription) (*SubscriptionContainer, error) {
	service, err := agent.GetCentralClient().GetAPIServiceByName(subscription.GetAPIServiceName())
	if err != nil {
		return nil, err
	}
	serviceinstance, err := agent.GetCentralClient().GetAPIServiceInstanceByName(subscription.GetAPIServiceInstanceName())
	if err != nil {
		return nil, err
	}
	servicerevision, err := agent.GetCentralClient().GetAPIRevisionByName(subscription.GetAPIServiceRevisionName())
	if err != nil {
		return nil, err
	}

	container := SubscriptionContainer{
		Sub:             subscription,
		Service:         service,
		ServiceInstance: serviceinstance,
		ServiceRevision: servicerevision,
	}
	if service.Metadata.ID == "" || serviceinstance.Metadata.ID == "" || servicerevision.Metadata.ID == "" {
		container.Valid = false
	} else {
		container.Valid = true
	}
	return &container, nil
}

// DumpDebug - Dumps debug information
func (container *SubscriptionContainer) DumpDebug() string {
	dump := "[ SubscriptionContainer [Subscription:" + container.Sub.GetName() + "]"
	if !container.Valid {
		dump = dump + " [Valid:FALSE] ]"
		return dump
	}
	dump = dump + " [Valid:TRUE]"
	dump = dump + fmt.Sprintf(" [IsEnvironmentDefined:%v]", container.IsEnvironmentDefined())
	dump = dump + fmt.Sprintf(" [IsExternalAPIIDDefined:%v]", container.IsExternalAPIIDDefined())
	dump = dump + fmt.Sprintf(" [IsExternalAPINameDefined:%v]", container.IsExternalAPINameDefined())
	dump = dump + fmt.Sprintf(" [Environment:%s]", container.GetEnvironmentName())
	dump = dump + fmt.Sprintf(" [RevisionName:%s]", container.GetRevisionName())
	dump = dump + fmt.Sprintf(" [ExternalAPIID:%s]", container.GetExternalAPIName())
	dump = dump + fmt.Sprintf(" [ExternalAPIName:%s]", container.GetExternalAPIName())
	dump = dump + " ]"
	return dump
}

// Debug - dumps debug information
func (container *SubscriptionContainer) Debug() string {
	dump := "[Attributes "
	service, err := agent.GetCentralClient().GetAPIServiceByName(container.Sub.GetAPIServiceName())
	if err != nil {
		log.Error("Did not work out", err)
		return "Error"
	}
	for k, v := range service.Attributes {
		dump = dump + fmt.Sprintf("[%s:%s]", k, v)
	}
	dump = dump + " ]"
	return dump
}

// ProcessUnsubscribeSubscription - Orchestrates entire unsubscription steps
func (container *SubscriptionContainer) ProcessUnsubscribeSubscription() error {
	log.Infof("Deprovisioning Subscription triggered [Environment/Org:%s] [Team:%s] [API-Product:%s] [Application:%s] [API:%s] [", container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.ServiceRevision.GetName(), container.Sub.GetID(), container.ServiceRevision.GetName())
	check, err := container.IsEnvironmentAsOrgAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [UNSUBSCRIBE] [IsEnvironmentAsOrgAvailable] ", err)
		return err
	}
	if !check {
		log.Warn("[ABORTING PROCESSING] [MIDDLEWARE] [UNSUBSCRIBE] [IsEnvironmentAsOrgAvailable] [Organization missing in Connector]", container.GetEnvironmentName())
		return errors.New("Organization missing in Connector:" + container.GetEnvironmentName())
	}

	err = container.RemoveTeamApp()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [UNSUBSCRIBE] [RemoveTeamApp]", err)
	}

	err = container.RemoveAPIProduct(true)
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [UNSUBSCRIBE] [RemoveAPIProduct]", err)
	}

	err = container.RemoveAPI(true)
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [UNSUBSCRIBE] [RemoveAPI]", err)
	}

	checkTeamApp, errCheckTeamApp := container.IsTeamAppAvailable()
	if errCheckTeamApp != nil {
		log.Error("[CHECK FAILED] [MIDDLEWARE] [UNSUBSCRIBE] [Check IsTeamAppAvailable]", errCheckTeamApp)
		return errors.New("TeamApp could not get removed from Connector.")
	}
	//API can still be referenced by another Product - no check here
	if checkTeamApp {
		log.Error("[CHECK FAILED] [MIDDLEWARE] [UNSUBSCRIBE] [CheckTeamApp] [Found Team App in Connector]")
		log.Errorf("Failed to remove Subscription [Environment/Org:%s] [Team:%s] [API-Product:%s] [Application:%s] [API:%s] [", container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.ServiceRevision.GetName(), container.Sub.GetID(), container.ServiceRevision.GetName())
		return errors.New("TeamApp still exists in Connector.")
	} else {
		log.Tracef("[SUCCESS] [MIDDLEWARE] [UNSUBSCRIBE] [MIDDLEWARE.ProcessUnsubscribeSubscription] [Environment/Org:%s] [Team:%s] [API-Product:%s] [Application:%s] [API:%s] [", container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.ServiceRevision.GetName(), container.Sub.GetID(), container.ServiceRevision.GetName())
		log.Infof("Successfully removed Subscription [Environment/Org:%s] [Team:%s] [API-Product:%s] [Application:%s] [API:%s] [", container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.ServiceRevision.GetName(), container.Sub.GetID(), container.ServiceRevision.GetName())
		username, errUsername := container.GetSubscriberUserName()
		if errUsername != nil {
			username = "undefined_username"
		}
		userEmail, errUserEmail := container.GetSubscriberEmailAddress()
		if errUserEmail != nil {
			userEmail = "undefined_email"
		}
		dto := notification.UnsubscribeMetaDataDto{
			Api:             container.GetRevisionName(),
			Team:            container.Sub.GetOwningTeamId(),
			Product:         container.GetRevisionName(),
			Application:     container.Sub.GetID(),
			Environment:     container.GetEnvironmentName(),
			Subscription:    container.Sub.GetName(),
			Subscriber:      username,
			Subscriberemail: userEmail,
		}
		okNotification, errNotification := notification.GetNotifierClient().NotifyUnsubscribe(dto)
		if errNotification != nil {
			log.Errorf("[ERROR] [MIDDLEWARE] [UNSUBSCRIBE] [Notification] [Notification failed] [%s]", errNotification)
		} else {
			if !okNotification {
				log.Error("[ERROR] [MIDDLEWARE] [UNSUBSCRIBE] [Notification] [Notification was not sent successfully]")
			}
		}
		return nil
	}
}

// ProcessSubscription  - Orchestrates entire subscription steps
func (container *SubscriptionContainer) ProcessSubscription() error {
	log.Infof("Provisioning Subscription triggered [Environment:%s] [Revision/API:%s][", container.GetEnvironmentName(), container.GetRevisionName())
	provisionedAPI := false
	provisionedAPIProduct := false
	provisionedTeam := false
	provisionedTeamApp := false

	check, err := container.IsEnvironmentAsOrgAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [IsEnvironmentAsOrgAvailable] ", err)
		return err
	}
	if !check {
		log.Warn("[ABORTING PROCESSING] [MIDDLEWARE] [SUBSCRIBE] [IsEnvironmentAsOrgAvailable] [Organization missing in Connector]", container.GetEnvironmentName())
		return errors.New("Organization missing in Connector:" + container.GetEnvironmentName())
	}
	//Environment / Organization exist in Connector
	check, err = container.IsConnectorAPIAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [IsConnectorAPIAvailable]", err)
		return err
	}
	if !check {
		err := container.PublishAPI()
		if err != nil {
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [PublishAPI]", err)
			return err
		}
		log.Trace("[OK] [MIDDLEWARE] [SUBSCRIBE] [PublishAPI] [API Published]")
		provisionedAPI = true

	}
	//API got published or already existed

	check, err = container.IsAPIProductAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [IsAPIProductAvailable]", err)
		return err
	}
	if !check {
		err := container.PublishAPIProduct()
		if err != nil {
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [PublishAPIProduct] [API-Product not provisioned]", err)
			return err
		}
		provisionedAPIProduct = true
		log.Trace("[OK] [MIDDLEWARE] [SUBSCRIBE] [PublishAPIProduct] [API-Product provisioned]")
	}

	check, err = container.IsConnectorTeamAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE][IsConnectorTeamAvailable]", err)
		return err
	}
	if !check {
		err := container.PublishTeam()
		if err != nil {
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [PublishTeam] [Team not provisioned]", err)
			return err
		}
		provisionedTeam = true
		log.Trace("[OK] [MIDDLEWARE] [SUBSCRIBE] [PublishTeam] [Team provisioned]")
	}

	check, err = container.IsTeamAppAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [IsTeamAppAvailable]", err)
		return err
	}
	if !check {
		_, err := container.PublishTeamApp()
		if err != nil {
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [PublishTeamApp] [TeamApp not provisioned]", err)
			return err
		}
		provisionedTeamApp = true
		log.Trace("[OK] [MIDDLEWARE] [SUBSCRIBE] [PublishTeamApp] [Team provisioned]")
	}

	if provisionedAPI || provisionedAPIProduct || provisionedTeam || provisionedTeamApp {
		log.Tracef("[SUCCESS] [MIDDLEWARE] [SUBSCRIBE] [MIDDLEWARE.ProcessSubscription] [API-Provisioned:%t] [API-Product-Provisioned:%t] [API-Provisioned:%t] [Team-Provisioned:%t] [Team-App-Provisioned:%t] [Environment:%s] [Revision/API:%s] [Team:%s] [TeamApp:%s]", provisionedAPI, provisionedAPIProduct, provisionedTeam, provisionedTeamApp, container.GetEnvironmentName(), container.GetRevisionName(), container.Sub.GetOwningTeamId(), container.Sub.GetID())

	} else {
		log.Tracef("[NO CHANGE] [MIDDLEWARE] [SUBSCRIBE] [API, API-Prodcut, Team, Team0-App already existed.] [Environment:%s] [Revision/API:%s] [Team:%s] [Team-App:%s]", container.GetEnvironmentName(), container.GetRevisionName(), container.Sub.GetOwningTeamId(), container.Sub.GetID())
	}

	userEmail, err := container.GetSubscriberEmailAddress()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [GetSubscriberEmail] [Could not retrieve Emailaddress of subscriber to hand over credentials]", err)
	}
	username, errUsername := container.GetSubscriberUserName()
	if errUsername != nil {
		username = "undefined_username"
	}
	applicationData, errAppData := container.GetTeamApp()
	if errAppData != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [GetTeamApp] [TeamApp Details could not get retrieved]", err)
		return errAppData
	}

	apiSpecs, errApiSpecs := container.GetAppApis()
	if errApiSpecs != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [GetAppApis] [Could not retrieve AsyncAPI specifications for application]", err)
		return errApiSpecs
	}

	dto := notification.SubscribeMetaDataDto{
		Api:             container.GetRevisionName(),
		Team:            container.Sub.GetOwningTeamId(),
		Product:         container.GetRevisionName(),
		Application:     container.Sub.GetID(),
		Environment:     container.GetEnvironmentName(),
		Subscription:    container.Sub.GetName(),
		Subscriber:      username,
		Subscriberemail: userEmail,
		ApplicationData: applicationData,
		ApiSpecs:        apiSpecs,
	}
	okNotification, errNotification := notification.GetNotifierClient().NotifySubscribe(dto)
	if errNotification != nil {
		log.Errorf("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [Notification] [Notification failed] [%s]", errNotification)
	} else {
		if !okNotification {
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [Notification] [Notification was not sent successfully]")
		}
	}
	log.Infof("Successfully provisioned Subscription [Environment:%s] [Revision/API:%s][", container.GetEnvironmentName(), container.GetRevisionName())
	return nil

}

// GetDummySuccessOrFault -for development only
func (container *SubscriptionContainer) GetDummySuccessOrFault(success bool) (bool, error) {
	return success, nil
}

func (container *SubscriptionContainer) GetSubscriberEmailAddress() (string, error) {
	userId := container.Sub.GetCreatedUserID()
	return agent.GetCentralClient().GetUserEmailAddress(userId)
}

func (container *SubscriptionContainer) GetSubscriberUserName() (string, error) {
	userId := container.Sub.GetCreatedUserID()
	return agent.GetCentralClient().GetUserName(userId)
}

// GetRevisionName - Facade to retrieve RevisionName
func (container *SubscriptionContainer) GetRevisionName() string {
	return container.ServiceRevision.GetName()
}

// IsEnvironmentDefined - Facade to check if environment is set in Service Instance
func (container *SubscriptionContainer) IsEnvironmentDefined() bool {
	return container.ServiceInstance.Metadata.Scope.Name != ""
}

// GetEnvironmentName - Facade to get environment name (Service Instance Scope Name)
func (container *SubscriptionContainer) GetEnvironmentName() string {
	return container.ServiceInstance.Metadata.Scope.Name
}

// IsExternalAPIIDDefined - Facade to check if External API ID is set
func (container *SubscriptionContainer) IsExternalAPIIDDefined() bool {
	return container.GetExternalAPIID() != ""
}

// IsExternalAPINameDefined - Facade to check if External API Name is set
func (container *SubscriptionContainer) IsExternalAPINameDefined() bool {
	return container.GetExternalAPIName() != ""
}

// GetExternalAPIID - Facade to get External API ID
func (container *SubscriptionContainer) GetExternalAPIID() string {
	return container.ServiceRevision.GetAttributes()["externalAPIID"]
}

// GetExternalAPIName - Facade to get External API Name
func (container *SubscriptionContainer) GetExternalAPIName() string {
	return container.ServiceRevision.GetAttributes()["externalAPIName"]
}

// GetAPISpec - Facade ti get API Spec (AsyncAPI spec)
func (container *SubscriptionContainer) GetAPISpec() string {
	return container.ServiceRevision.Spec.Definition.Value
}

//IsEnvironmentAsOrgAvailable - Facade to check in Connector if an organization exists that has the same name as Axway Environment of the subscription
func (container *SubscriptionContainer) IsEnvironmentAsOrgAvailable() (bool, error) {
	if container.GetEnvironmentName() == "" {
		return false, nil
	}
	return connector.GetAdminConnector().IsOrgRegistered(container.GetEnvironmentName())
}

//IsConnectorAPIAvailable - Facade to check via Connector if API already exists
func (container *SubscriptionContainer) IsConnectorAPIAvailable() (bool, error) {
	return connector.GetOrgConnector().IsAPIAvailable(container.GetEnvironmentName(), container.GetRevisionName())
}

//IsAPIProductAvailable - Facade to check via Connector if API-Product exists
func (container *SubscriptionContainer) IsAPIProductAvailable() (bool, error) {
	//by convention api and product have same name: revisionName
	return connector.GetOrgConnector().IsAPIProductAvailable(container.GetEnvironmentName(), container.GetRevisionName())
}

//IsConnectorTeamAvailable - Facade to check via Connector if Team exists
func (container *SubscriptionContainer) IsConnectorTeamAvailable() (bool, error) {
	return connector.GetOrgConnector().IsTeamAvailable(container.GetEnvironmentName(), container.Sub.GetOwningTeamId())
}

//IsTeamAppAvailable - Facade to check via Connector if Team Application exists
func (container *SubscriptionContainer) IsTeamAppAvailable() (bool, error) {
	return connector.GetOrgConnector().IsTeamAppAvailable(container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.Sub.GetID())
}

//PublishAPIProduct - Facade to publish via Connector an API Product (idempotent)
func (container *SubscriptionContainer) PublishAPIProduct() error {
	//todo cross-check all environments will share same protocols
	connectorEnvs, err := connector.GetOrgConnector().GetListEnvironments(container.GetEnvironmentName())
	if err != nil {
		return err
	}
	if len(connectorEnvs) == 0 {
		log.Warnf("[PublishAPIProduct] [MIDDLEWARE] [There are no Environments provisioned in Connector for the organization] [Org:%s]", container.GetEnvironmentName())
	}
	envNames := make([]string, 0)
	protocols := make([]connector.Protocol, 0)
	permissions := container.Service.GetAttributes()
	for _, endpoint := range container.ServiceInstance.Spec.Endpoint {

		idx := sort.Search(len(connectorEnvs), func(i int) bool {
			return endpoint.Host == connectorEnvs[i].Host
		})
		if idx < len(connectorEnvs) && connectorEnvs[idx].Host == endpoint.Host {
			envNames = append(envNames, connectorEnvs[idx].Name)
			protocolVersion, found := connectorEnvs[idx].ProtocolVersion[endpoint.Protocol]
			if found {
				protocols = append(protocols, connector.Protocol{Name: connector.ProtocolName(endpoint.Protocol), Version: &protocolVersion})
			} else {
				//todo detailed error message
				return errors.New("Protocol/Version not in Environment")
			}
		} else {
			return errors.New("Environment not found")
		}
	}

	return connector.GetOrgConnector().PublishAPIProduct(container.GetEnvironmentName(), container.GetRevisionName(), []string{container.GetRevisionName()}, envNames, protocols, permissions)
}

//RemoveAPI - Facade to remove via connector an API
func (container *SubscriptionContainer) RemoveAPI(ignoreConflict bool) error {
	return connector.GetOrgConnector().RemoveAPI(container.GetEnvironmentName(), container.GetRevisionName(), ignoreConflict)
}

//RemoveAPIProduct - Facade to remove via Connector an API Product
func (container *SubscriptionContainer) RemoveAPIProduct(ignoreConflict bool) error {
	return connector.GetOrgConnector().RemoveAPIProduct(container.GetEnvironmentName(), container.GetRevisionName(), ignoreConflict)
}

//GetTeamApp - Facade to retrieve App as generic JSON
func (container *SubscriptionContainer) GetTeamApp() (map[string]interface{}, error) {
	return connector.GetOrgConnector().GetTeamApp(container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.Sub.GetID())
}

//GetAppApis - Facade to retrieve all AsyncApi specs of an app
func (container *SubscriptionContainer) GetAppApis() ([]*map[string]interface{}, error) {
	apiNames, error := connector.GetOrgConnector().GetAppApiNames(container.GetEnvironmentName(), container.Sub.GetID())
	if error != nil {
		return nil, error
	}
	//apiSpecs := []map[string]interface{}
	apiSpecs := make([]*map[string]interface{}, 0)

	for _, apiName := range *apiNames {
		apiSpec, errorSpec := connector.GetOrgConnector().GetAppApiSpecification(container.GetEnvironmentName(), container.Sub.GetID(), apiName)
		if errorSpec != nil {
			return nil, errorSpec
		}
		apiSpecs = append(apiSpecs, apiSpec)
	}
	return apiSpecs, nil
}

//RemoveTeamApp - Facade to remove via Connector a Team Application
func (container *SubscriptionContainer) RemoveTeamApp() error {
	apiProducts := make([]string, 0)
	apiProducts = append(apiProducts, container.GetRevisionName())
	return connector.GetOrgConnector().RemoveTeamApp(container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.Sub.GetID())
}

//PublishTeamApp - Facade to publish via Connector a Team Application
func (container *SubscriptionContainer) PublishTeamApp() (*connector.Credentials, error) {
	apiProducts := make([]string, 0)
	apiProducts = append(apiProducts, container.GetRevisionName())
	return connector.GetOrgConnector().PublishTeamApp(container.GetEnvironmentName(), container.Sub.GetOwningTeamId(), container.Sub.GetID(), "Created by Axway-Agent", apiProducts)
}

//PublishAPI - Facade to publish via Connector an API
func (container *SubscriptionContainer) PublishAPI() error {
	decodedAPISpec, err := base64.StdEncoding.DecodeString(container.GetAPISpec())
	if err != nil {
		return err
	}
	return connector.GetOrgConnector().PublishAPI(container.GetEnvironmentName(), container.GetRevisionName(), decodedAPISpec)
}

//PublishTeam - Facade to publish via Connector a Team
func (container *SubscriptionContainer) PublishTeam() error {
	return connector.GetOrgConnector().PublishTeam(container.GetEnvironmentName(), container.Sub.GetOwningTeamId())
}
