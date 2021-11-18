package gateway

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
	"sort"
	"strings"
)

type AxwaySubscription interface {
	IsValid() bool
	LogText(c *SubscriptionContainer) string
	GetServiceAttributes() map[string]string
	GetSolaceAsyncApiAppInternalId() string
	GetCatalogItemName() string
	SetSolaceAsyncApiAppInternalId(id string)
	SetSubscriptionCredentials(credentials *connector.SolaceCredentialsDto)
	GetSubscriptionCredentials() *connector.SolaceCredentialsDto
	GetSubscriberEmailAddress()
	GetSubscriberUserName() string
	GetRevisionName() string
	IsEnvironmentDefined() bool
	GetEnvironmentName() string
	IsExternalAPIIDDefined() bool
	IsExternalAPINameDefined() bool
	GetExternalAPIID() string
	GetExternalAPIName() string
	GetAPISpec() string
	GetSubscriptionName() string
	GetSubscriptionAPIServiceName() string
	GetSubscriptionId() string
	GetSubscriptionOwningTeamId() string
	GetSubscriptionCatalogItemId() string
	GetSubscriptionPropertyValue(key string) string
	GetServiceInstanceMetadataScopeName() string
	GetServiceInstanceSpecEndpoints() []AxwayEndpoint
}

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
	solaceCallbackApi           bool
	solaceAsyncApiAppInternalId string
}

type SubscriptionMiddleware struct {
	as AxwaySubscription
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
	return &container, nil
}

// LogText - Extracts Logging Details
func LogText(c *SubscriptionContainer) string {
	return fmt.Sprintf("[Environment/Org:%s] [Team:%s] [API-Product:%s] [Application:%s] [API:%s]", c.GetEnvironmentName(), c.GetSubscriptionOwningTeamId(), c.GetRevisionName(), c.GetSubscriptionId(), c.GetRevisionName())
}

func (container *SubscriptionContainer) GetSolaceAsyncApiAppInternalId() string {
	return container.solaceAsyncApiAppInternalId
}

func (container *SubscriptionContainer) GetCatalogItemName() string {
	return container.catalogItemName
}

func (container *SubscriptionContainer) SetSolaceAsyncApiAppInternalId(id string) {
	container.solaceAsyncApiAppInternalId = id
}

func (container *SubscriptionContainer) SetSubscriptionCredentials(credentials *connector.SolaceCredentialsDto) {
	container.subscriptionCredentials = credentials
}
func (container *SubscriptionContainer) GetSubscriptionCredentials() *connector.SolaceCredentialsDto {
	return container.subscriptionCredentials
}

// GetSubscriberEmailAddress - Returns Email
func (container *SubscriptionContainer) GetSubscriberEmailAddress() string {
	return container.subscriberEmailAddress
}

//todo refactor and remove error return type
// GetSubscriberUserName - Returns Username
func (container *SubscriptionContainer) GetSubscriberUserName() string {
	return container.subscriberUserName
}

// GetRevisionName - Facade to retrieve RevisionName
func (container *SubscriptionContainer) GetRevisionName() string {
	return container.serviceRevision.GetName()
}

// IsEnvironmentDefined - Facade to check if environment is set in Service Instance
func (container *SubscriptionContainer) IsEnvironmentDefined() bool {
	return container.GetServiceInstanceMetadataScopeName() != ""
}

// GetEnvironmentName - Facade to get environment name (Service Instance Scope Name)
func (container *SubscriptionContainer) GetEnvironmentName() string {
	return container.GetServiceInstanceMetadataScopeName()
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
	return container.serviceRevision.GetAttributes()["externalAPIID"]
}

// GetExternalAPIName - Facade to get External API Name
func (container *SubscriptionContainer) GetExternalAPIName() string {
	return container.serviceRevision.GetAttributes()["externalAPIName"]
}

// GetAPISpec - Facade ti get API Spec (AsyncAPI spec)
func (container *SubscriptionContainer) GetAPISpec() string {
	return container.serviceRevision.Spec.Definition.Value
}

func (c *SubscriptionContainer) IsValid() bool {
	c.GetSubscriberEmailAddress()
	return c.valid
}

func (c *SubscriptionContainer) GetServiceAttributes() map[string]string {
	return c.service.Attributes
}

func (c *SubscriptionContainer) GetSubscriptionName() string {
	return c.sub.GetName()
}

func (c *SubscriptionContainer) GetSubscriptionAPIServiceName() string {
	return c.sub.GetAPIServiceName()
}

func (c *SubscriptionContainer) GetSubscriptionId() string {
	return c.sub.GetID()
}

func (c *SubscriptionContainer) GetSubscriptionOwningTeamId() string {
	return c.sub.GetOwningTeamId()
}

func (c *SubscriptionContainer) GetSubscriptionCatalogItemId() string {
	return c.sub.GetCatalogItemID()
}

func (c *SubscriptionContainer) GetSubscriptionPropertyValue(key string) string {
	return c.sub.GetPropertyValue(key)
}

func (c *SubscriptionContainer) GetServiceInstanceMetadataScopeName() string {
	return c.serviceInstance.Metadata.Scope.Name
}

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

// DumpDebug - Dumps debug information
func (container *SubscriptionContainer) DumpDebug() string {
	dump := "[ SubscriptionContainer [Subscription:" + container.GetSubscriptionName() + "]"
	if !container.IsValid() {
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
	service, err := agent.GetCentralClient().GetAPIServiceByName(container.GetSubscriptionAPIServiceName())
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
func ProcessUnsubscribeSubscription(container *SubscriptionContainer) error {
	log.Infof("Deprovisioning Subscription triggered %s", LogText(container))
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
		log.Errorf("Failed to remove Subscription %s", LogText(container))
		return errors.New("TeamApp still exists in Connector.")
	} else {
		log.Tracef("[SUCCESS] [MIDDLEWARE] [UNSUBSCRIBE] [MIDDLEWARE.ProcessUnsubscribeSubscription] %s", LogText(container))
		log.Infof("Successfully removed Subscription %s", LogText(container))
		username := container.GetSubscriberUserName()
		userEmail := container.GetSubscriberEmailAddress()
		dto := notification.UnsubscribeMetaDataDto{
			Api:             container.GetRevisionName(),
			Team:            container.GetSubscriptionOwningTeamId(),
			Product:         container.GetRevisionName(),
			Application:     container.GetSubscriptionId(),
			Environment:     container.GetEnvironmentName(),
			Subscription:    container.GetSubscriptionName(),
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
func ProcessSubscription(container *SubscriptionContainer) error {
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
			log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [PublishAPIProduct] [API-Product not provisioned] ", err)
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
		log.Tracef("[SUCCESS] [MIDDLEWARE] [SUBSCRIBE] [MIDDLEWARE.ProcessSubscription] [API-Provisioned:%t] [API-Product-Provisioned:%t] [API-Provisioned:%t] [Team-Provisioned:%t] [Team-App-Provisioned:%t] [Environment:%s] [Revision/API:%s] [Team:%s] [TeamApp:%s]", provisionedAPI, provisionedAPIProduct, provisionedTeam, provisionedTeamApp, container.GetEnvironmentName(), container.GetRevisionName(), container.GetSubscriptionOwningTeamId(), container.GetSubscriptionId())

	} else {
		log.Tracef("[NO CHANGE] [MIDDLEWARE] [SUBSCRIBE] [API, API-Prodcut, Team, Team0-App already existed.] [Environment:%s] [Revision/API:%s] [Team:%s] [Team-App:%s]", container.GetEnvironmentName(), container.GetRevisionName(), container.GetSubscriptionOwningTeamId(), container.GetSubscriptionId())
	}

	userEmail := container.GetSubscriberEmailAddress()
	username := container.GetSubscriberUserName()
	subscriptionCredentials, applicationData, errAppData := container.GetTeamApp()

	if errAppData != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [GetTeamApp] [TeamApp Details could not get retrieved]", err)
		return errAppData
	}

	container.SetSubscriptionCredentials(subscriptionCredentials)
	//extranct internalId from Solace Connector App
	if v, ok := applicationData["internalName"]; ok {
		container.SetSolaceAsyncApiAppInternalId(fmt.Sprintf("%v", v))
	} else {
		container.SetSolaceAsyncApiAppInternalId("unknown internal id")
	}

	apiSpecs, errApiSpecs := container.GetAppApis()
	if errApiSpecs != nil {
		log.Error("[ERROR] [MIDDLEWARE] [SUBSCRIBE] [GetAppApis] [Could not retrieve AsyncAPI specifications for application]", err)
		return errApiSpecs
	}

	dto := notification.SubscribeMetaDataDto{
		Api:             container.GetRevisionName(),
		Team:            container.GetSubscriptionOwningTeamId(),
		Product:         container.GetRevisionName(),
		Application:     container.GetSubscriptionId(),
		Environment:     container.GetEnvironmentName(),
		Subscription:    container.GetSubscriptionName(),
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

func (container *SubscriptionContainer) NotifySuccess(trigger string, message string, correlationId string) (bool, error) {
	userEmail := container.GetSubscriberEmailAddress()
	username := container.GetSubscriberUserName()

	dto := notification.MonitorDataDto{
		Api:             container.GetRevisionName(),
		Team:            container.GetSubscriptionOwningTeamId(),
		Product:         container.GetRevisionName(),
		Application:     container.GetSubscriptionId(),
		Environment:     container.GetEnvironmentName(),
		Subscription:    container.GetSubscriptionName(),
		Subscriber:      username,
		Subscriberemail: userEmail,
		Trigger:         notification.MonitorDataTrigger(trigger),
		Success:         true,
		Message:         &message,
		CorrelationId:   "undefined",
	}

	okNotification, err := notification.GetNotifierClient().NotifySuccessMonitor(dto)
	if err != nil {
		log.Errorf("[ERROR] [MIDDLEWARE] [NotifySuccess]  [Notification failed] [%s]", err)
		return false, err
	} else {
		if !okNotification {
			log.Error("[ERROR] [MIDDLEWARE] [NotifySuccess] [Notification was not sent successfully]")
		}
		return false, nil
	}
	return true, nil
}

func (container *SubscriptionContainer) NotifyFailure(trigger string, message string, correlationId string) (bool, error) {
	userEmail := container.GetSubscriberEmailAddress()
	username := container.GetSubscriberUserName()

	dto := notification.MonitorDataDto{
		Api:             container.GetRevisionName(),
		Team:            container.GetSubscriptionOwningTeamId(),
		Product:         container.GetRevisionName(),
		Application:     container.GetSubscriptionId(),
		Environment:     container.GetEnvironmentName(),
		Subscription:    container.GetSubscriptionName(),
		Subscriber:      username,
		Subscriberemail: userEmail,
		Trigger:         notification.MonitorDataTrigger(trigger),
		Success:         false,
		CorrelationId:   "undefined",
		Message:         &message,
	}

	okNotification, err := notification.GetNotifierClient().NotifyFailureMonitor(dto)
	if err != nil {
		log.Errorf("[ERROR] [MIDDLEWARE] [NotifyFailure]  [Notification failed] [%s]", err)
		return false, err
	} else {
		if !okNotification {
			log.Error("[ERROR] [MIDDLEWARE] [NotifyFailure] [Notification was not sent successfully]")
		}
		return false, nil
	}
	return true, nil
}

// GetDummySuccessOrFault -for development only
func (container *SubscriptionContainer) GetDummySuccessOrFault(success bool) (bool, error) {
	return success, nil
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
	return connector.GetOrgConnector().IsTeamAvailable(container.GetEnvironmentName(), container.GetSubscriptionOwningTeamId())
}

//IsTeamAppAvailable - Facade to check via Connector if Team Application exists
func (container *SubscriptionContainer) IsTeamAppAvailable() (bool, error) {
	return connector.GetOrgConnector().IsTeamAppAvailable(container.GetEnvironmentName(), container.GetSubscriptionOwningTeamId(), container.GetSubscriptionId())
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
	permissions := container.GetServiceAttributes()
	for _, endpoint := range container.GetServiceInstanceSpecEndpoints() {

		idx := sort.Search(len(connectorEnvs), func(i int) bool {
			return endpoint.Host == connectorEnvs[i].Host
		})
		if idx < len(connectorEnvs) && connectorEnvs[idx].Host == endpoint.Host {
			envNames = append(envNames, connectorEnvs[idx].Name)
			protocolVersion, found := connectorEnvs[idx].ProtocolVersion[endpoint.Protocol]
			if found {
				ver := connector.CommonVersion(protocolVersion)
				protocols = append(protocols, connector.Protocol{
					Name:    connector.ProtocolName(endpoint.Protocol),
					Version: &ver})
			} else {
				return errors.New(fmt.Sprintf("Protocol/Version not in Environment [Host:%s] [Port:%d] [Protocol:%s]", endpoint.Host, endpoint.Port, endpoint.Protocol))
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
func (container *SubscriptionContainer) GetTeamApp() (*connector.SolaceCredentialsDto, map[string]interface{}, error) {
	return connector.GetOrgConnector().GetTeamApp(container.GetEnvironmentName(), container.GetSubscriptionOwningTeamId(), container.GetSubscriptionId())
}

//GetAppApis - Facade to retrieve all AsyncApi specs of an app
func (container *SubscriptionContainer) GetAppApis() ([]*map[string]interface{}, error) {
	apiNames, error := connector.GetOrgConnector().GetAppApiNames(container.GetEnvironmentName(), container.GetSubscriptionId())
	if error != nil {
		return nil, error
	}
	//apiSpecs := []map[string]interface{}
	apiSpecs := make([]*map[string]interface{}, 0)

	for _, apiName := range *apiNames {
		apiSpec, errorSpec := connector.GetOrgConnector().GetAppApiSpecification(container.GetEnvironmentName(), container.GetSubscriptionId(), apiName)
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
	return connector.GetOrgConnector().RemoveTeamApp(container.GetEnvironmentName(), container.GetSubscriptionOwningTeamId(), container.GetSubscriptionId())
}

//PublishTeamApp - Facade to publish via Connector a Team Application
func (container *SubscriptionContainer) PublishTeamApp() (*connector.Credentials, error) {
	apiProducts := make([]string, 0)
	apiProducts = append(apiProducts, container.GetRevisionName())
	trustedCNSList := make([]string, 0)
	var webHooks *connector.SolaceWebhook = nil
	if len(container.GetSubscriptionPropertyValue(solace.SolaceHttpMethod)) > 0 {
		trustedCNS := strings.TrimSpace(container.GetSubscriptionPropertyValue(solace.SolaceCallbackTrustedCNS))
		if len(trustedCNS) > 0 {
			trustedCNSList = strings.Split(trustedCNS, ",")
		}
		webHooks = &connector.SolaceWebhook{
			HttpMethod:               container.GetSubscriptionPropertyValue(solace.SolaceHttpMethod),
			CallbackUrl:              container.GetSubscriptionPropertyValue(solace.SolaceCallback),
			AuthenticationMethod:     container.GetSubscriptionPropertyValue(solace.SolaceAuthenticationMethod),
			AuthenticationIdentifier: container.GetSubscriptionPropertyValue(solace.SolaceAuthenticationIdentifier),
			AuthenticationSecret:     container.GetSubscriptionPropertyValue(solace.SolaceAuthenticationSecret),
			InvocationOrder:          container.GetSubscriptionPropertyValue(solace.SolaceInvocationOrder),
			TrusedCNs:                trustedCNSList,
		}
	}
	return connector.GetOrgConnector().PublishTeamApp(container.GetEnvironmentName(), container.GetSubscriptionOwningTeamId(), container.GetSubscriptionId(), "Created by Axway-Agent", apiProducts, webHooks)
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
	return connector.GetOrgConnector().PublishTeam(container.GetEnvironmentName(), container.GetSubscriptionOwningTeamId())
}
