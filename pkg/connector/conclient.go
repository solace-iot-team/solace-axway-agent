package connector

import (
	"bytes"
	"context"
	"fmt"
	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/pkg/errors"
	hc "github.com/solace-iot-team/agent-sdk/pkg/util/healthcheck"
	"github.com/solace-iot-team/agent-sdk/pkg/util/log"
	"github.com/solace-iot-team/solace-axway-agent/pkg/config"
	"net"
	"net/http"
	url2 "net/url"
	"strings"
	"time"
)

const connectorName = "Solace Connector"

// ConclientHTTPError - Detailed HTTP-Error
type ConclientHTTPError struct {
	ClientFunction string
	HTTPStatusCode int
	Response       string
}

// Error - Created detailed HTTP-Error
func (c *ConclientHTTPError) Error() string {
	return fmt.Sprintf("Call [%s] was not successfull. [Http-Status:%d] [Response:%s]", c.ClientFunction, c.HTTPStatusCode, c.Response)
}

// SolaceEnvironment Holds connection details for Solacce VPN Environment
type SolaceEnvironment struct {
	Name            string
	ServiceID       string
	Host            string
	ProtocolVersion map[string]string
}

type connectorClients struct {
	AdminConnector *Access
	OrgConnector   *Access
}

//Access Holds refernce to HTTP-Client to Solace Connector
type Access struct {
	Client *ClientWithResponses
}

//Attribute Solace Connector Attribute
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

var connectors = connectorClients{}

//Initialize sets connector client as admin and as org-admin
func Initialize(gatewayCfg *config.GatewayConfig) error {
	orgClient, err := NewConnectorOrgClient(gatewayCfg)
	if err != nil {
		return err
	}
	adminClient, err := NewConnectorAdminClient(gatewayCfg)
	if err != nil {
		return err
	}

	connectors.OrgConnector = &Access{
		Client: orgClient,
	}
	connectors.AdminConnector = &Access{
		Client: adminClient,
	}

	//register HealthChecker
	hc.RegisterHealthcheck(connectorName, "solace", connectors.AdminConnector.Healthcheck)

	return nil
}

// NewConnectorAdminClient - Creates a new Gateway Client
func NewConnectorAdminClient(gatewayCfg *config.GatewayConfig) (*ClientWithResponses, error) {
	basicAuthProvider, basicAuthProviderErr := securityprovider.NewSecurityProviderBasicAuth(gatewayCfg.ConnectorAdminUser, gatewayCfg.ConnectorAdminPassword)
	if basicAuthProviderErr != nil {
		panic(basicAuthProviderErr)
	}
	myclient, err := NewClientWithResponses(gatewayCfg.ConnectorURL, WithRequestEditorFn(basicAuthProvider.Intercept))
	if err != nil {
		return nil, err
	}
	return myclient, nil
}

// NewConnectorOrgClient - Creates a new Gateway Client
func NewConnectorOrgClient(gatewayCfg *config.GatewayConfig) (*ClientWithResponses, error) {
	basicAuthProvider, basicAuthProviderErr := securityprovider.NewSecurityProviderBasicAuth(gatewayCfg.ConnectorOrgUser, gatewayCfg.ConnectorOrgPassword)
	if basicAuthProviderErr != nil {
		panic(basicAuthProviderErr)
	}
	myclient, err := NewClientWithResponses(gatewayCfg.ConnectorURL, WithRequestEditorFn(basicAuthProvider.Intercept))
	if err != nil {
		return nil, err
	}
	return myclient, nil
}

// Healthcheck - verify connection to Solace connector
func (c *Access) Healthcheck(name string) *hc.Status {
	// Set a default response
	s := hc.Status{
		Result: hc.OK,
	}
	result, err := c.IsHealthCheck()
	if err != nil {
		s = hc.Status{
			Result:  hc.FAIL,
			Details: err.Error(),
		}
		return &s
	}
	if !result {
		s = hc.Status{
			Result:  hc.FAIL,
			Details: "Not successfull",
		}
	}
	return &s
}

// GetAdminConnector - connector as admin
func GetAdminConnector() *Access {
	return connectors.AdminConnector
}

// GetOrgConnector - connector as org-admin
func GetOrgConnector() *Access {
	return connectors.OrgConnector
}

func defaultTimeout() time.Duration {
	return 30 * time.Second
}

// IsHealthCheck - checks if Connector is accessible as admin
func (c *Access) IsHealthCheck() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	//just get the list of all organizations
	// todo replace with a health check on connector side
	result, err := c.Client.ListOrganizationsWithResponse(ctx)
	if err != nil {
		return false, err
	}
	if result.StatusCode() != http.StatusOK {
		return false, fmt.Errorf("Solace-Connector is accessible but returned HTTP-Status-Code: %v", result.StatusCode())
	}
	return result.StatusCode() == http.StatusOK, nil
}

// IsOrgRegistered - checks if there is an organization in the connector
func (c *Access) IsOrgRegistered(orgName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.GetOrganizationWithResponse(ctx, Organization(orgName))
	if err != nil {
		return false, err
	}
	return result.StatusCode() == http.StatusOK, nil
}

// IsAPIAvailable - checks if there is already an API existing
func (c *Access) IsAPIAvailable(orgName string, apiName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	params := GetApiParams{}
	result, err := c.Client.GetApiWithResponse(ctx, Organization(orgName), ApiName(apiName), &params)
	if err != nil {
		return false, err
	}
	return result.StatusCode() == http.StatusOK, nil
}

// IsAPIProductAvailable - checks if there is already an API-Product existing
func (c *Access) IsAPIProductAvailable(orgName string, productName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.GetApiProductWithResponse(ctx, Organization(orgName), ApiProductName(productName))
	if err != nil {
		return false, err
	}
	return result.StatusCode() == http.StatusOK, nil
}

// IsTeamAvailable - checks if there is already an API-Team existing
func (c *Access) IsTeamAvailable(orgName string, teamName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.GetTeamWithResponse(ctx, Organization(orgName), TeamName(teamName))
	if err != nil {
		return false, err
	}
	return result.StatusCode() == http.StatusOK, nil
}

// IsTeamAppAvailable - checks if there is already a Team-App existing
func (c *Access) IsTeamAppAvailable(orgName string, teamName string, appName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	//topicSyntace := GetTeamAppParams(TopicSyntax: GetTeamAppParamsTopicSyntax("mqtt"))
	params := GetTeamAppParamsTopicSyntax("mqtt")
	topicSyntax := GetTeamAppParams{
		TopicSyntax: &params,
	}
	result, err := c.Client.GetTeamAppWithResponse(ctx, Organization(orgName), TeamName(teamName), AppName(appName), &topicSyntax)
	if err != nil {
		return false, err
	}
	return result.StatusCode() == http.StatusOK, nil
}

// GetListEnvironments - provides all environments
func (c *Access) GetListEnvironments(orgName string) ([]SolaceEnvironment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	format := ListEnvironmentsParamsFormat("full")
	params := ListEnvironmentsParams{
		Format: &format,
	}
	listEnvironments, err := c.Client.ListEnvironmentsWithResponse(ctx, Organization(orgName), &params)
	if err != nil {
		return nil, err
	}
	if listEnvironments.StatusCode() != http.StatusOK {
		return nil, errors.New("Solace-Connector did not HTTP-200 for listEnvironments")
	}
	solaceEnvs := make([]SolaceEnvironment, 0)
	for _, env := range *listEnvironments.JSON200 {
		host, _ := deriveHostFromProtocols(env)
		//todo log error for debugging / follow up in logs

		solaceEnvs = append(solaceEnvs, SolaceEnvironment{
			Name:            env.Name,
			ServiceID:       env.ServiceId,
			Host:            host,
			ProtocolVersion: extractProtocolVersionMap(env)})
	}
	return solaceEnvs, nil
}

func extractProtocolVersionMap(env EnvironmentListItem) map[string]string {
	protocolVersionMap := make(map[string]string)
	for _, endpoint := range env.ExposedProtocols {
		protocolVersionMap[string(endpoint.Name)] = *endpoint.Version
	}
	return protocolVersionMap
}
func deriveHostFromProtocols(env EnvironmentListItem) (string, error) {
	for _, endpoint := range *env.MessagingProtocols {
		if endpoint.Uri != nil {
			url, err := url2.Parse(*endpoint.Uri)
			if err == nil {
				host, _, _ := net.SplitHostPort(url.Host)
				return host, nil
			}
		}
	}
	return "", errors.New("Could not derive a Host out of Environment Protocol List")
}

// RemoveTeamApp - removes the Team-Application
func (c *Access) RemoveTeamApp(orgName string, teamName string, appName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.DeleteTeamAppWithResponse(ctx, Organization(orgName), TeamName(teamName), AppName(appName))
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT.RemoveTeamApp] [DeleteTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] ", orgName, teamName, appName)
		return err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "DeleteTeamAppWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Debugf("[FAULT] [CONCLIENT.RemoveTeamApp] [DeleteTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] [%s]", orgName, teamName, appName, returnError.Error())
		return returnError
	}
	log.Debugf("[OK] [CONCLIENT.RemoveTeamApp] [DeleteTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] ", orgName, teamName, appName)
	return nil
}

// PublishTeamApp - publishes TeamApp
func (c *Access) PublishTeamApp(orgName string, teamName string, appName string, displayName string, apiProducts []string) (*Credentials, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	credentials := Credentials{
		ExpiresAt: -1,
		IssuedAt:  nil,
		Secret:    nil,
	}
	payload := CreateTeamAppJSONRequestBody{
		Name:        appName,
		DisplayName: &displayName,
		ApiProducts: apiProducts,
		Credentials: credentials,
	}
	result, err := c.Client.CreateTeamAppWithResponse(ctx, Organization(orgName), TeamName(teamName), payload)
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT.PublishTeamApp] [CreateTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] [displayName:%s] [apiProducts:%s]", orgName, teamName, appName, displayName, strings.Join(apiProducts, ","))
		return nil, err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateTeamAppWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Debugf("[FAULT] [CONCLIENT.PublishTeamApp] [CreateTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] [displayName:%s] [apiProducts:%s] [%s]", orgName, teamName, appName, displayName, strings.Join(apiProducts, ","), returnError.Error())
		return nil, returnError
	}
	log.Debugf("[OK] [CONCLIENT.PublishTeamApp] [CreateTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] [displayName:%s] [apiProducts:%s]", orgName, teamName, appName, displayName, strings.Join(apiProducts, ","))

	return &result.JSON201.Credentials, nil
}

// PublishTeam - publishes / creates a team
func (c *Access) PublishTeam(orgName string, teamName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	payload := CreateTeamJSONBody{
		Name:        teamName,
		DisplayName: teamName,
	}
	result, err := c.Client.CreateTeamWithResponse(ctx, Organization(orgName), CreateTeamJSONRequestBody(payload))
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT.PublishTeam] [CreateTeamWithResponse] [orgName:%s] [teamName:%s]", orgName, teamName)
		return err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateTeamWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Debugf("[FAULT] [CONCLIENT.PublishTeam] [CreateTeamWithResponse][orgName:%s] [teamName:%s][%s]", orgName, teamName, returnError.Error())
		return returnError
	}
	log.Debugf("[OK] [CONCLIENT.PublishTeam] [CreateTeamWithResponse][orgName:%s] [teamName:%s][%s]", orgName, teamName)
	return nil
}

// RemoveAPIProduct - removes Api-Product
func (c *Access) RemoveAPIProduct(orgName string, productName string, ignoreConflictResponse bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	result, err := c.Client.DeleteApiProductWithResponse(ctx, Organization(orgName), ApiProductName(productName))
	if err != nil {
		log.Debugf("[ERROR] [CONCLIENT.DeleteApiProductWithResponse] [orgName:%s] [productName:%s] ", orgName, productName, err.Error())
		return err
	}
	if ignoreConflictResponse {
		if result.StatusCode() == http.StatusConflict {
			log.Debugf("[INFO] [CONCLIENT.DeleteApiProductWithResponse] [orgName:%s] [apiName:%s] [Tried to delete API-Product but still referenced] [HTTP-Status:%d] ", orgName, productName, result.StatusCode())
			return nil
		}
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "DeleteApiProductWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Debugf("[FAULT] [CONCLIENT.RemoveAPIProduct] [orgName:%s]  [productName:%s]  [%s]", orgName, productName, returnError.Error())
		return returnError
	}
	log.Debugf("[OK] [CONCLIENT.RemoveAPIProduct] [orgName:%s]  [productName:%s]  [%s]", orgName, productName)
	return nil
}

// PublishAPIProduct - publishes API-Product
func (c *Access) PublishAPIProduct(orgName string, productName string, apiNames []string, environments []string, protocols []Protocol, permissions map[string]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	a := APIProductApprovalTypeAuto
	d := "Created by Solace-Axway-Agent"
	attributes := make([]struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}, 0)
	for k, v := range permissions {
		attributes = append(attributes, Attribute{Name: k, Value: v})
	}
	payload := CreateApiProductJSONRequestBody{
		Name:         productName,
		Apis:         apiNames,
		ApprovalType: &a,
		Description:  &d,
		DisplayName:  productName,
		Environments: &environments,
		Protocols:    &protocols,
		PubResources: make([]string, 0),
		SubResources: make([]string, 0),
		Attributes:   attributes,
	}
	result, err := c.Client.CreateApiProductWithResponse(ctx, Organization(orgName), CreateApiProductJSONRequestBody(payload))
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT.PublishAPIProduct] [CreateApiProductWithResponse] [orgName:%s] [productName:%s] [apiNames:%s] [environments:%s] [protocols:%s]", orgName, productName, strings.Join(apiNames, ","), strings.Join(environments, ","), strings.Join(protocolsToString(protocols), ","))
		return err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateApiProductWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Debugf("[FAULT] [CONCLIENT.PublishAPIProduct] [CreateApiProductWithResponse] [orgName:%s] [productName:%s] [apiNames:%s] [environments:%s] [protocols:%s] [%s]", orgName, productName, strings.Join(apiNames, ","), strings.Join(environments, ","), strings.Join(protocolsToString(protocols), ","), returnError.Error())
		return returnError
	}
	log.Debugf("[OK] [CONCLIENT.PublishAPIProduct] [Http-Status:%d] [CreateApiProductWithResponse] [orgName:%s] [productName:%s] [apiNames:%s] [environments:%s] [protocols:%s]", result.StatusCode(), orgName, productName, strings.Join(apiNames, ","), strings.Join(environments, ","), strings.Join(protocolsToString(protocols), ","))
	return nil
}

func protocolsToString(protocols []Protocol) []string {
	result := make([]string, 0)
	for _, item := range protocols {
		text := string(item.Name)
		if item.Version != nil {
			text = text + ":" + *item.Version
		}
		result = append(result, text)
	}
	return result
}

// RemoveAPI - removes API
func (c *Access) RemoveAPI(orgName string, apiName string, ignoreConflictResponse bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	result, err := c.Client.DeleteApiWithResponse(ctx, Organization(orgName), ApiName(apiName))
	if err != nil {
		log.Debugf("[ERROR] [CONCLIENT.DeleteApiWithResponse] [orgName:%s] [apiName:%s] ", orgName, apiName, err.Error())
		return err
	}
	if ignoreConflictResponse {
		if result.StatusCode() == http.StatusConflict {
			log.Debugf("[INFO] [CONCLIENT.RemoveAPI] [orgName:%s] [apiName:%s] [Tried to delete API but still referenced] [HTTP-Status:%d] ", orgName, apiName, result.StatusCode())
			return nil
		}
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "DeleteApiWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Debugf("[FAULT] [CONCLIENT.RemoveAPI] [orgName:%s] [apiName:%s]  [%s]", orgName, apiName, returnError.Error())
		return returnError
	}
	log.Debugf("[OK] [CONCLIENT.RemoveAPI] [Http-Status:%d] [orgName:%s] [apiName:%s]  ", result.StatusCode(), orgName, apiName)
	return nil
}

// PublishAPI - publishes API
func (c *Access) PublishAPI(orgName string, apiName string, apiSpec []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	result, err := c.Client.CreateApiWithBodyWithResponse(ctx, Organization(orgName), ApiName(apiName), "text/plain", bytes.NewReader(apiSpec))
	if err != nil {
		log.Debugf("[ERROR] [CONCLIENT.PublishAPI] [orgName:%s] [apiName:%s] [apiSpec-length:%d] [%s]", orgName, apiName, len(apiSpec), err.Error())
		return err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateApiWithBodyWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Debugf("[FAULT] [CONCLIENT.PublishAPI] [orgName:%s] [apiName:%s] [apiSpec-length:%d] [%s]", orgName, apiName, len(apiSpec), returnError.Error())
		return returnError
	}
	log.Debugf("[OK] [CONCLIENT.PublishAPI] [Http-Status:%d] [orgName:%s] [apiName:%s] [apiSpec-length:%d] ", result.StatusCode(), orgName, apiName, len(apiSpec))
	return nil
}
