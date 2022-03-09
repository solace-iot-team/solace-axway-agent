package middleware

import (
	"encoding/base64"
	"fmt"
	"github.com/Axway/agent-sdk/pkg/agent"
	"github.com/Axway/agent-sdk/pkg/apic"
	"github.com/Axway/agent-sdk/pkg/apic/apiserver/models/management/v1alpha1"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/pkg/errors"
	"github.com/solace-iot-team/solace-axway-agent/pkg/connector"
	"github.com/solace-iot-team/solace-axway-agent/pkg/notification"
	"github.com/solace-iot-team/solace-axway-agent/pkg/solace"
	"strings"
)

// AxwaySubscription represents Axway Subscription content
type AxwaySubscription interface {
	LogText() string
	GetServiceAttributes() map[string]string
	GetSolaceAsyncAPIAppInternalID() string
	GetCatalogItemName() string
	SetSolaceAsyncAPIAppInternalID(id string)
	SetSubscriptionCredentials(credentials *connector.SolaceCredentialsDto)
	GetSubscriptionCredentials() *connector.SolaceCredentialsDto
	GetSubscriberEmailAddress() string
	GetSubscriberUserName() string
	GetRevisionName() string
	GetRevisionId() string
	IsEnvironmentDefined() bool
	GetEnvironmentName() string
	IsExternalAPIIDDefined() bool
	IsExternalAPINameDefined() bool
	GetExternalAPIID() string
	GetExternalAPIName() string
	GetAPISpec() string
	GetSubscriptionName() string
	GetSubscriptionAPIServiceName() string
	GetSubscriptionID() string
	GetSubscriptionOwningTeamID() string
	GetSubscriptionCatalogItemID() string
	GetSubscriptionPropertyValue(key string) string
	GetServiceInstanceMetadataScopeName() string
	GetServiceInstanceSpecEndpoints() []AxwayEndpoint
}

// AxwayEndpoint represents an Axway Endpoint
type AxwayEndpoint struct {
	Host     string
	Port     int32
	Protocol string
}

// SubscriptionContainer - holds additional information for a subscription
type SubscriptionContainer struct {
	// ConceptMapping
	// Environment.LogicalName - Org
	// Subscription.OwningTeamId - Team
	// ServiceRevision.Name - APIProduct (Name)
	// Subscription.Id - Application (Name)
	// ServiceRevision.Name - API (Name)
	connectorOrg                string
	valid                       bool
	sub                         apic.Subscription
	service                     *v1alpha1.APIService
	serviceInstance             *v1alpha1.APIServiceInstance
	serviceRevision             *v1alpha1.APIServiceRevision
	consumerInstance            *v1alpha1.ConsumerInstance
	catalogItemName             string
	subscriberEmailAddress      string
	subscriberUserName          string
	subscriptionCredentials     *connector.SolaceCredentialsDto
	solaceCallbackAPI           bool
	solaceAsyncAPIAppInternalID string
}

// SubscriptionMiddleware holds AxwaySubscription and exposes functionality
type SubscriptionMiddleware struct {
	valid        bool
	connectorOrg string
	AxSub        AxwaySubscription
}

// NewSubscriptionMiddleware - creates new SubscriptionContainer
func NewSubscriptionMiddleware(subscription apic.Subscription, connectorOrg string) (*SubscriptionMiddleware, error) {
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
	catalogItemName, err := agent.GetCentralClient().GetCatalogItemName(subscription.GetCatalogItemID())
	if err != nil {
		return nil, err
	}
	emailAddress, err := agent.GetCentralClient().GetUserEmailAddress(subscription.GetCreatedUserID())
	if err != nil {
		return nil, err
	}
	userName, err := agent.GetCentralClient().GetUserName(subscription.GetCreatedUserID())

	container := SubscriptionContainer{
		sub:                    subscription,
		service:                service,
		serviceInstance:        serviceinstance,
		serviceRevision:        servicerevision,
		catalogItemName:        catalogItemName,
		subscriberEmailAddress: emailAddress,
		subscriberUserName:     userName,
	}
	if service.Metadata.ID == "" || serviceinstance.Metadata.ID == "" || servicerevision.Metadata.ID == "" {
		container.valid = false
	} else {
		container.valid = true
	}
	middleware := SubscriptionMiddleware{
		AxSub:        &container,
		valid:        false,
		connectorOrg: connectorOrg,
	}
	return &middleware, nil
}

func (c *SubscriptionMiddleware) GetOrg() string {
	if c.connectorOrg == "" {
		//default Axway Environment Name = Solace Connector Org Name
		return c.AxSub.GetEnvironmentName()
	} else {
		return c.connectorOrg
	}
}

// LogText - Extracts Logging Details
func (c *SubscriptionContainer) LogText() string {
	return fmt.Sprintf("[Axway Environment:%s] [Team:%s] [API-Product:%s] [Application:%s] [API:%s]", c.GetEnvironmentName(), c.GetSubscriptionOwningTeamID(), c.GetRevisionName(), c.GetSubscriptionID(), c.GetRevisionName())
}

// GetSolaceAsyncAPIAppInternalID - getter
func (c *SubscriptionContainer) GetSolaceAsyncAPIAppInternalID() string {
	return c.solaceAsyncAPIAppInternalID
}

// GetCatalogItemName - getter
func (c *SubscriptionContainer) GetCatalogItemName() string {
	return c.catalogItemName
}

// SetSolaceAsyncAPIAppInternalID - setter
func (c *SubscriptionContainer) SetSolaceAsyncAPIAppInternalID(id string) {
	c.solaceAsyncAPIAppInternalID = id
}

// SetSubscriptionCredentials - setter
func (c *SubscriptionContainer) SetSubscriptionCredentials(credentials *connector.SolaceCredentialsDto) {
	c.subscriptionCredentials = credentials
}

// GetSubscriptionCredentials - getter
func (c *SubscriptionContainer) GetSubscriptionCredentials() *connector.SolaceCredentialsDto {
	return c.subscriptionCredentials
}

// GetSubscriberEmailAddress - Returns Email
func (c *SubscriptionContainer) GetSubscriberEmailAddress() string {
	return c.subscriberEmailAddress
}

// GetSubscriberUserName - getter
func (c *SubscriptionContainer) GetSubscriberUserName() string {
	return c.subscriberUserName
}

// GetRevisionName - Facade to retrieve RevisionName
func (c *SubscriptionContainer) GetRevisionName() string {
	return c.serviceRevision.GetName()
}

// GetRevisionId - Facade to retrieve RevisionId (metadata.id)
func (c *SubscriptionContainer) GetRevisionId() string {
	return c.serviceRevision.Metadata.ID
}

// IsEnvironmentDefined - Facade to check if environment is set in Service Instance
func (c *SubscriptionContainer) IsEnvironmentDefined() bool {
	return c.GetServiceInstanceMetadataScopeName() != ""
}

// GetEnvironmentName - Facade to get environment name (Service Instance Scope Name)
func (c *SubscriptionContainer) GetEnvironmentName() string {
	return c.GetServiceInstanceMetadataScopeName()
}

// IsExternalAPIIDDefined - Facade to check if External API ID is set
func (c *SubscriptionContainer) IsExternalAPIIDDefined() bool {
	return c.GetExternalAPIID() != ""
}

// IsExternalAPINameDefined - Facade to check if External API Name is set
func (c *SubscriptionContainer) IsExternalAPINameDefined() bool {
	return c.GetExternalAPIName() != ""
}

// GetExternalAPIID - Facade to get External API ID
func (c *SubscriptionContainer) GetExternalAPIID() string {
	return c.serviceRevision.GetAttributes()["externalAPIID"]
}

// GetExternalAPIName - Facade to get External API Name
func (c *SubscriptionContainer) GetExternalAPIName() string {
	return c.serviceRevision.GetAttributes()["externalAPIName"]
}

// GetAPISpec - Facade ti get API Spec (AsyncAPI spec)
func (c *SubscriptionContainer) GetAPISpec() string {
	return c.serviceRevision.Spec.Definition.Value
}

// GetServiceAttributes getter
func (c *SubscriptionContainer) GetServiceAttributes() map[string]string {
	return c.service.Attributes
}

// GetSubscriptionName getter
func (c *SubscriptionContainer) GetSubscriptionName() string {
	return c.sub.GetName()
}

// GetSubscriptionAPIServiceName getter
func (c *SubscriptionContainer) GetSubscriptionAPIServiceName() string {
	return c.sub.GetAPIServiceName()
}

// GetSubscriptionID getter
func (c *SubscriptionContainer) GetSubscriptionID() string {
	return c.sub.GetID()
}

// GetSubscriptionOwningTeamID getter
func (c *SubscriptionContainer) GetSubscriptionOwningTeamID() string {
	return c.sub.GetOwningTeamID()
}

// GetSubscriptionCatalogItemID getter
func (c *SubscriptionContainer) GetSubscriptionCatalogItemID() string {
	return c.sub.GetCatalogItemID()
}

// GetSubscriptionPropertyValue getter
func (c *SubscriptionContainer) GetSubscriptionPropertyValue(key string) string {
	return c.sub.GetPropertyValue(key)
}

// GetServiceInstanceMetadataScopeName getter
func (c *SubscriptionContainer) GetServiceInstanceMetadataScopeName() string {
	return c.serviceInstance.Metadata.Scope.Name
}

// GetServiceInstanceSpecEndpoints getter
func (c *SubscriptionContainer) GetServiceInstanceSpecEndpoints() []AxwayEndpoint {
	endpoints := make([]AxwayEndpoint, 0)
	for _, ep := range c.serviceInstance.Spec.Endpoint {
		endpoints = append(endpoints, AxwayEndpoint{
			Host:     ep.Host,
			Port:     ep.Port,
			Protocol: ep.Protocol,
		})
	}
	return endpoints
}

// ProcessUnsubscribeSubscription - Orchestrates entire unsubscription steps
func (sm *SubscriptionMiddleware) ProcessUnsubscribeSubscription() error {
	log.Infof("Deprovisioning Subscription triggered %s", sm.AxSub.LogText())
	check, err := sm.IsOrgAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [UNSUBSCRIBE] [IsEnvironmentAsOrgAvailable] ", err)
		return err
	}
	if !check {
		log.Warn("[ABORTING PROCESSING] [MIDDLEWARE] [UNSUBSCRIBE] [IsEnvironmentAsOrgAvailable] [Organization missing in Connector]", sm.GetOrg())
		return errors.New("Organization missing in Connector:" + sm.GetOrg())
	}

	err = sm.RemoveTeamApp()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [UNSUBSCRIBE] [RemoveTeamApp]", err)
	}

	err = sm.RemoveAPIProduct(true)
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [UNSUBSCRIBE] [RemoveAPIProduct]", err)
	}

	err = sm.RemoveAPI(true)
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [UNSUBSCRIBE] [RemoveAPI]", err)
	}

	checkTeamApp, errCheckTeamApp := sm.IsTeamAppAvailable()
	if errCheckTeamApp != nil {
		log.Error("[CHECK FAILED] [MIDDLEWARE] [UNSUBSCRIBE] [Check IsTeamAppAvailable]", errCheckTeamApp)
		return errors.New("TeamApp could not get removed from Connector")
	}
	//API can still be referenced by another Product - no check here
	if checkTeamApp {
		log.Error("[CHECK FAILED] [MIDDLEWARE] [UNSUBSCRIBE] [CheckTeamApp] [Found Team App in Connector]")
		log.Errorf("Failed to remove Subscription %s", sm.AxSub.LogText())
		return errors.New("TeamApp still exists in Connector")
	}
	log.Tracef("[SUCCESS] [MIDDLEWARE] [UNSUBSCRIBE] [MIDDLEWARE.ProcessUnsubscribeSubscription] %s", sm.AxSub.LogText())
	log.Infof("Successfully removed Subscription %s", sm.AxSub.LogText())
	username := sm.AxSub.GetSubscriberUserName()
	userEmail := sm.AxSub.GetSubscriberEmailAddress()
	dto := notification.UnsubscribeMetaDataDto{
		API:             sm.AxSub.GetRevisionName(),
		Team:            sm.AxSub.GetSubscriptionOwningTeamID(),
		Product:         sm.AxSub.GetRevisionName(),
		Application:     sm.AxSub.GetSubscriptionID(),
		Environment:     sm.AxSub.GetEnvironmentName(),
		Subscription:    sm.AxSub.GetSubscriptionName(),
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

// ProcessSubscription  - Orchestrates entire subscription steps
func (sm *SubscriptionMiddleware) ProcessSubscription() error {
	log.Infof("Provisioning Subscription triggered [Axway Environment:%s] [Connector Org:%s] [Revision/API:%s] [RevisionId:%s]", sm.AxSub.GetEnvironmentName(), sm.GetOrg(), sm.AxSub.GetRevisionName(), sm.AxSub.GetRevisionId())
	provisionedAPI := false
	provisionedAPIProduct := false
	provisionedTeam := false
	provisionedTeamApp := false

	check, err := sm.IsOrgAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [IsOrgAvailable] ", err)
		return err
	}
	if !check {
		log.Warn("[ABORTING PROCESSING] [MIDDLEWARE] [SUBSCRIBE] [IsOrgAvailable] [Organization missing in Connector]", sm.GetOrg())
		return errors.New("Organization missing in Connector:" + sm.GetOrg())
	}
	//Environment / Organization exist in Connector
	check, err = sm.IsConnectorAPIAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [IsConnectorAPIAvailable]", err)
		return err
	}
	if !check {
		err := sm.PublishAPI()
		if err != nil {
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [PublishAPI]", err)
			return err
		}
		log.Trace("[OK] [MIDDLEWARE] [SUBSCRIBE] [PublishAPI] [API Published]")
		provisionedAPI = true

	}
	//API got published or already existed

	check, err = sm.IsAPIProductAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [IsAPIProductAvailable]", err)
		return err
	}
	if !check {
		err := sm.PublishAPIProduct()
		if err != nil {
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [PublishAPIProduct] [API-Product not provisioned] ", err)
			return err
		}
		provisionedAPIProduct = true
		log.Trace("[OK] [MIDDLEWARE] [SUBSCRIBE] [PublishAPIProduct] [API-Product provisioned]")
	}

	check, err = sm.IsConnectorTeamAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE][IsConnectorTeamAvailable]", err)
		return err
	}
	if !check {
		err := sm.PublishTeam()
		if err != nil {
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [PublishTeam] [Team not provisioned]", err)
			return err
		}
		provisionedTeam = true
		log.Trace("[OK] [MIDDLEWARE] [SUBSCRIBE] [PublishTeam] [Team provisioned]")
	}

	check, err = sm.IsTeamAppAvailable()
	if err != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [IsTeamAppAvailable]", err)
		return err
	}
	if !check {
		_, err := sm.PublishTeamApp()
		if err != nil {
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [PublishTeamApp] [TeamApp not provisioned]", err)
			return err
		}
		provisionedTeamApp = true
		log.Trace("[OK] [MIDDLEWARE] [SUBSCRIBE] [PublishTeamApp] [Team provisioned]")
	}

	if provisionedAPI || provisionedAPIProduct || provisionedTeam || provisionedTeamApp {
		log.Tracef("[SUCCESS] [MIDDLEWARE] [SUBSCRIBE] [MIDDLEWARE.ProcessSubscription] [API-Provisioned:%t] [API-Product-Provisioned:%t] [API-Provisioned:%t] [Team-Provisioned:%t] [Team-App-Provisioned:%t] [Environment:%s] [Revision/API:%s] [Team:%s] [TeamApp:%s]", provisionedAPI, provisionedAPIProduct, provisionedTeam, provisionedTeamApp, sm.AxSub.GetEnvironmentName(), sm.AxSub.GetRevisionName(), sm.AxSub.GetSubscriptionOwningTeamID(), sm.AxSub.GetSubscriptionID())

	} else {
		log.Tracef("[NO CHANGE] [MIDDLEWARE] [SUBSCRIBE] [API, API-Prodcut, Team, Team-App already existed.] [Axway Environment:%s] [Connector Org:%s] [Revision/API:%s] [Team:%s] [Team-App:%s]", sm.AxSub.GetEnvironmentName(), sm.GetOrg(), sm.AxSub.GetRevisionName(), sm.AxSub.GetSubscriptionOwningTeamID(), sm.AxSub.GetSubscriptionID())
	}

	userEmail := sm.AxSub.GetSubscriberEmailAddress()
	username := sm.AxSub.GetSubscriberUserName()
	subscriptionCredentials, applicationData, errAppData := sm.GetTeamApp()

	if errAppData != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [GetTeamApp] [TeamApp Details could not get retrieved]", err)
		return errAppData
	}

	sm.AxSub.SetSubscriptionCredentials(subscriptionCredentials)
	//extranct internalId from Solace Connector App
	if v, ok := applicationData["internalName"]; ok {
		sm.AxSub.SetSolaceAsyncAPIAppInternalID(fmt.Sprintf("%v", v))
	} else {
		sm.AxSub.SetSolaceAsyncAPIAppInternalID("unknown internal id")
	}

	apiSpecs, errAPISpecs := sm.GetAppApis()
	if errAPISpecs != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [GetAppApis] [Could not retrieve AsyncAPI specifications for application]", err)
		return errAPISpecs
	}

	dto := notification.SubscribeMetaDataDto{
		API:             sm.AxSub.GetRevisionName() + " (" + sm.AxSub.GetRevisionId() + ")",
		Team:            sm.AxSub.GetSubscriptionOwningTeamID(),
		Product:         sm.AxSub.GetRevisionName() + " (" + sm.AxSub.GetRevisionId() + ")",
		Application:     sm.AxSub.GetSubscriptionID(),
		Environment:     sm.AxSub.GetEnvironmentName(),
		Subscription:    sm.AxSub.GetSubscriptionName(),
		Subscriber:      username,
		Subscriberemail: userEmail,
		ApplicationData: applicationData,
		APISpecs:        apiSpecs,
	}
	okNotification, errNotification := notification.GetNotifierClient().NotifySubscribe(dto)
	if errNotification != nil {
		log.Errorf("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [Notification] [Notification failed] [%s]", errNotification)
	} else {
		if !okNotification {
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [Notification] [Notification was not sent successfully]")
		}
	}
	log.Infof("Successfully provisioned Subscription [Environment:%s] [Connector Org:%s] [Revision/API:%s [RevisionId:%s][", sm.AxSub.GetEnvironmentName(), sm.GetOrg(), sm.AxSub.GetRevisionName(), sm.AxSub.GetRevisionId())
	return nil

}

// NotifySuccess notifies success
func (sm *SubscriptionMiddleware) NotifySuccess(trigger string, message string, correlationID string) (bool, error) {
	userEmail := sm.AxSub.GetSubscriberEmailAddress()
	username := sm.AxSub.GetSubscriberUserName()

	dto := notification.MonitorDataDto{
		API:             sm.AxSub.GetRevisionName() + " (" + sm.AxSub.GetRevisionId() + ")",
		Team:            sm.AxSub.GetSubscriptionOwningTeamID(),
		Product:         sm.AxSub.GetRevisionName() + " (" + sm.AxSub.GetRevisionId() + ")",
		Application:     sm.AxSub.GetSubscriptionID(),
		Environment:     sm.AxSub.GetEnvironmentName(),
		Subscription:    sm.AxSub.GetSubscriptionName(),
		Subscriber:      username,
		Subscriberemail: userEmail,
		Trigger:         notification.MonitorDataTrigger(trigger),
		Success:         true,
		Message:         &message,
		CorrelationID:   "undefined",
	}

	okNotification, err := notification.GetNotifierClient().NotifySuccessMonitor(dto)
	if err != nil {
		log.Errorf("[ERROR] [MIDDLEWARE] [NotifySuccess]  [Notification failed] [%s]", err)
		return false, err
	}
	if !okNotification {
		log.Error("[ERROR] [MIDDLEWARE] [NotifySuccess] [Notification was not sent successfully]")
		return false, nil
	}
	return true, nil
}

// NotifyFailure publishes failure notification
func (sm *SubscriptionMiddleware) NotifyFailure(trigger string, message string, correlationID string) (bool, error) {
	userEmail := sm.AxSub.GetSubscriberEmailAddress()
	username := sm.AxSub.GetSubscriberUserName()

	dto := notification.MonitorDataDto{
		API:             sm.AxSub.GetRevisionName() + " (" + sm.AxSub.GetRevisionId() + ")",
		Team:            sm.AxSub.GetSubscriptionOwningTeamID(),
		Product:         sm.AxSub.GetRevisionName() + " (" + sm.AxSub.GetRevisionId() + ")",
		Application:     sm.AxSub.GetSubscriptionID(),
		Environment:     sm.AxSub.GetEnvironmentName(),
		Subscription:    sm.AxSub.GetSubscriptionName(),
		Subscriber:      username,
		Subscriberemail: userEmail,
		Trigger:         notification.MonitorDataTrigger(trigger),
		Success:         false,
		CorrelationID:   "undefined",
		Message:         &message,
	}

	okNotification, err := notification.GetNotifierClient().NotifyFailureMonitor(dto)
	if err != nil {
		log.Errorf("[ERROR] [MIDDLEWARE] [NotifyFailure]  [Notification failed] [%s]", err)
		return false, err
	}
	if !okNotification {
		log.Error("[ERROR] [MIDDLEWARE] [NotifyFailure] [Notification was not sent successfully]")
		return false, nil
	}
	return true, nil
}

// GetDummySuccessOrFault -for development only
func (sm *SubscriptionMiddleware) GetDummySuccessOrFault(success bool) (bool, error) {
	return success, nil
}

//IsOrgAvailable - Facade to check in Connector if an organization exists that has the same name AxSub Axway Environment of the subscription
func (sm *SubscriptionMiddleware) IsOrgAvailable() (bool, error) {
	if sm.GetOrg() == "" {
		return false, nil
	}
	return connector.GetAdminConnector().IsOrgRegistered(sm.GetOrg())
}

//IsConnectorAPIAvailable - Facade to check via Connector if API already exists
func (sm *SubscriptionMiddleware) IsConnectorAPIAvailable() (bool, error) {
	return connector.GetOrgConnector().IsAPIAvailable(sm.GetOrg(), sm.AxSub.GetRevisionId())
}

//IsAPIProductAvailable - Facade to check via Connector if API-Product exists
func (sm *SubscriptionMiddleware) IsAPIProductAvailable() (bool, error) {
	//by convention api and product have same name: revisionName
	return connector.GetOrgConnector().IsAPIProductAvailable(sm.GetOrg(), sm.AxSub.GetRevisionId())
}

//IsConnectorTeamAvailable - Facade to check via Connector if Team exists
func (sm *SubscriptionMiddleware) IsConnectorTeamAvailable() (bool, error) {
	return connector.GetOrgConnector().IsTeamAvailable(sm.GetOrg(), sm.AxSub.GetSubscriptionOwningTeamID())
}

//IsTeamAppAvailable - Facade to check via Connector if Team Application exists
func (sm *SubscriptionMiddleware) IsTeamAppAvailable() (bool, error) {
	return connector.GetOrgConnector().IsTeamAppAvailable(sm.GetOrg(), sm.AxSub.GetSubscriptionOwningTeamID(), sm.AxSub.GetSubscriptionID())
}

//PublishAPIProduct - Facade to publish via Connector an API Product (idempotent)
func (sm *SubscriptionMiddleware) PublishAPIProduct() error {
	agent.GetCentralConfig().GetEnvironmentName()
	connectorEnvs, err := connector.GetOrgConnector().GetListEnvironments(sm.GetOrg())
	if err != nil {
		return err
	}
	if len(connectorEnvs) == 0 {
		log.Warnf("[PublishAPIProduct] [MIDDLEWARE] [There are no Solace Connector Environments provisioned in Connector for Solace Connector Organization] [Org:%s]", sm.GetOrg())
		return errors.New("[PublishAPIProduct] []MIDDLEWARE] [There are no Solace Connector Environments provisioned ]")
	}

	protocols := make([]connector.Protocol, 0)
	lookupProtocolNames := make(map[string]bool)
	envNames := make([]string, 0)

	for _, connectorEnv := range connectorEnvs {
		countEndpointsFound := 0
		for _, axwayEndpoint := range sm.AxSub.GetServiceInstanceSpecEndpoints() {
			solaceProtocolName, found := solace.AxwaySolaceProtocolMapping[axwayEndpoint.Protocol]
			if !found {
				log.Warn("[PublishAPIProduct] [MIDDLEWARE] [Unmapped Axway protocol name:%s]", axwayEndpoint.Protocol)
				return errors.New("[PublishAPIProduct] []MIDDLEWARE] [Unknown Axway Protocol Name]")
			}
			found, protocolVersion, err := connectorEnv.FindEnvProtocolVersion(axwayEndpoint.Host, fmt.Sprint(axwayEndpoint.Port), solaceProtocolName)
			if err != nil {
				log.Tracef("[PublishAPIProduct] [MIDDLEWARE] [error looking up protocol version in Connector Env] [Org:%s] [Env:%s]", sm.GetOrg(), connectorEnv.Name)
				return err
			}
			if found {
				countEndpointsFound++
				if !lookupProtocolNames[solaceProtocolName] {
					lookupProtocolNames[solaceProtocolName] = true
					ver := connector.CommonVersion(protocolVersion)
					protocols = append(protocols, connector.Protocol{
						Name:    connector.ProtocolName(solaceProtocolName),
						Version: &ver})
				}
			}
		}
		//an environment must support all axwayEndpoints
		if countEndpointsFound == len(sm.AxSub.GetServiceInstanceSpecEndpoints()) {
			envNames = append(envNames, connectorEnv.Name)
		}
	}
	if len(envNames) == 0 {
		endpointInfo := make(map[string]string)
		for _, axwayEndpoint := range sm.AxSub.GetServiceInstanceSpecEndpoints() {
			endpointText, found := endpointInfo[axwayEndpoint.Host]
			if found {
				text := endpointText + ", Port:" + fmt.Sprint(axwayEndpoint.Port) + " Axway-Protocol:" + axwayEndpoint.Protocol
				endpointInfo[axwayEndpoint.Host] = text
			} else {
				text := "Port:" + fmt.Sprint(axwayEndpoint.Port) + " Axway-Protocol:" + axwayEndpoint.Protocol
				endpointInfo[axwayEndpoint.Host] = text
			}
		}
		debugText := ""
		for host, protocols := range endpointInfo {
			debugText = fmt.Sprintf("%s[ %s - %s] ", debugText, host, protocols)
		}
		log.Warnf("[PublishAPIProduct] []MIDDLEWARE] [No fitting exposed Solace Connector Environment Protocols found for Axway Endpoints] [Org:%s] [%s]", sm.GetOrg(), debugText)
		return errors.New("[PublishAPIProduct] []MIDDLEWARE] [No fitting exposed Solace Connector Environment Protocols found for Axway Endpoints]")
	}

	permissions := sm.AxSub.GetServiceAttributes()
	return connector.GetOrgConnector().PublishAPIProduct(sm.GetOrg(), sm.AxSub.GetRevisionId(), []string{sm.AxSub.GetRevisionId()}, envNames, protocols, permissions)
}

func containsString(s []string, item string) bool {
	for _, a := range s {
		if a == item {
			return true
		}
	}
	return false
}

//RemoveAPI - Facade to remove via connector an API
func (sm *SubscriptionMiddleware) RemoveAPI(ignoreConflict bool) error {
	return connector.GetOrgConnector().RemoveAPI(sm.GetOrg(), sm.AxSub.GetRevisionId(), ignoreConflict)
}

//RemoveAPIProduct - Facade to remove via Connector an API Product
func (sm *SubscriptionMiddleware) RemoveAPIProduct(ignoreConflict bool) error {
	return connector.GetOrgConnector().RemoveAPIProduct(sm.GetOrg(), sm.AxSub.GetRevisionId(), ignoreConflict)
}

//GetTeamApp - Facade to retrieve App AxSub generic JSON
func (sm *SubscriptionMiddleware) GetTeamApp() (*connector.SolaceCredentialsDto, map[string]interface{}, error) {
	return connector.GetOrgConnector().GetTeamApp(sm.GetOrg(), sm.AxSub.GetSubscriptionOwningTeamID(), sm.AxSub.GetSubscriptionID())
}

//GetAppApis - Facade to retrieve all AsyncApi specs of an app
func (sm *SubscriptionMiddleware) GetAppApis() ([]*map[string]interface{}, error) {
	apiNames, error := connector.GetOrgConnector().GetAppAPINames(sm.GetOrg(), sm.AxSub.GetSubscriptionID())
	if error != nil {
		return nil, error
	}
	//apiSpecs := []map[string]interface{}
	apiSpecs := make([]*map[string]interface{}, 0)

	for _, apiName := range *apiNames {
		apiSpec, errorSpec := connector.GetOrgConnector().GetAppAPISpecification(sm.GetOrg(), sm.AxSub.GetSubscriptionID(), apiName)
		if errorSpec != nil {
			return nil, errorSpec
		}
		apiSpecs = append(apiSpecs, apiSpec)
	}
	return apiSpecs, nil
}

//RemoveTeamApp - Facade to remove via Connector a Team Application
func (sm *SubscriptionMiddleware) RemoveTeamApp() error {
	apiProducts := make([]string, 0)
	apiProducts = append(apiProducts, sm.AxSub.GetRevisionId())
	return connector.GetOrgConnector().RemoveTeamApp(sm.GetOrg(), sm.AxSub.GetSubscriptionOwningTeamID(), sm.AxSub.GetSubscriptionID())
}

//PublishTeamApp - Facade to publish via Connector a Team Application
func (sm *SubscriptionMiddleware) PublishTeamApp() (*connector.Credentials, error) {
	apiProducts := make([]string, 0)
	apiProducts = append(apiProducts, sm.AxSub.GetRevisionId())
	trustedCNSList := make([]string, 0)
	appAttributes := make(map[string]string)
	var webHooks *connector.SolaceWebhook = nil
	if len(sm.AxSub.GetSubscriptionPropertyValue(solace.SolaceHTTPMethod)) > 0 {
		trustedCNS := strings.TrimSpace(sm.AxSub.GetSubscriptionPropertyValue(solace.SolaceCallbackTrustedCNS))
		if len(trustedCNS) > 0 {
			trustedCNSList = strings.Split(trustedCNS, ",")
		}
		webHooks = &connector.SolaceWebhook{
			HTTPMethod:               sm.AxSub.GetSubscriptionPropertyValue(solace.SolaceHTTPMethod),
			CallbackURL:              sm.AxSub.GetSubscriptionPropertyValue(solace.SolaceCallback),
			AuthenticationMethod:     sm.AxSub.GetSubscriptionPropertyValue(solace.SolaceAuthenticationMethod),
			AuthenticationIdentifier: sm.AxSub.GetSubscriptionPropertyValue(solace.SolaceAuthenticationIdentifier),
			AuthenticationSecret:     sm.AxSub.GetSubscriptionPropertyValue(solace.SolaceAuthenticationSecret),
			InvocationOrder:          sm.AxSub.GetSubscriptionPropertyValue(solace.SolaceInvocationOrder),
			TrusedCNs:                trustedCNSList,
		}
	}
	if len(sm.AxSub.GetSubscriptionPropertyValue(solace.SolaceClientOrigin)) > 0 {
		appAttributes[solace.SolaceClientOrigin] = sm.AxSub.GetSubscriptionPropertyValue(solace.SolaceClientOrigin)
	}
	return connector.GetOrgConnector().PublishTeamApp(sm.GetOrg(), sm.AxSub.GetSubscriptionOwningTeamID(), sm.AxSub.GetSubscriptionID(), "Created by Axway-Agent", apiProducts, webHooks, appAttributes)
}

//PublishAPI - Facade to publish via Connector an API
func (sm *SubscriptionMiddleware) PublishAPI() error {
	decodedAPISpec, err := base64.StdEncoding.DecodeString(sm.AxSub.GetAPISpec())
	if err != nil {
		return err
	}
	return connector.GetOrgConnector().PublishAPI(sm.GetOrg(), sm.AxSub.GetRevisionId(), decodedAPISpec)
}

//PublishTeam - Facade to publish via Connector a Team
func (sm *SubscriptionMiddleware) PublishTeam() error {
	return connector.GetOrgConnector().PublishTeam(sm.GetOrg(), sm.AxSub.GetSubscriptionOwningTeamID())
}
