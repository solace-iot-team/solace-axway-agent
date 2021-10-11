package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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

type SolaceCredentialsDto struct {
	ConsumerKey    string
	ConsumerSecret *string
	IssuedAt       *float32
	ExpiresAt      *float32
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
func Initialize(gatewayCfg *config.ConnectorConfig) error {
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
func NewConnectorAdminClient(gatewayCfg *config.ConnectorConfig) (*ClientWithResponses, error) {
	basicAuthProvider, basicAuthProviderErr := securityprovider.NewSecurityProviderBasicAuth(gatewayCfg.ConnectorAdminUser, gatewayCfg.ConnectorAdminPassword)
	if basicAuthProviderErr != nil {
		panic(basicAuthProviderErr)
	}
	myclient, err := NewClientWithResponses(gatewayCfg.ConnectorURL, WithTlsConfig(gatewayCfg.ConnectorInsecureSkipVerify), WithRequestEditorFn(basicAuthProvider.Intercept))
	if err != nil {
		return nil, err
	}
	return myclient, nil
}

// NewConnectorOrgClient - Creates a new Gateway Client
func NewConnectorOrgClient(gatewayCfg *config.ConnectorConfig) (*ClientWithResponses, error) {
	basicAuthProvider, basicAuthProviderErr := securityprovider.NewSecurityProviderBasicAuth(gatewayCfg.ConnectorOrgUser, gatewayCfg.ConnectorOrgPassword)
	if basicAuthProviderErr != nil {
		panic(basicAuthProviderErr)
	}
	myclient, err := NewClientWithResponses(gatewayCfg.ConnectorURL, WithTlsConfig(gatewayCfg.ConnectorInsecureSkipVerify), WithRequestEditorFn(basicAuthProvider.Intercept))
	if err != nil {
		return nil, err
	}
	return myclient, nil
}

func WithTlsConfig(insecureSkipVerify bool) ClientOption {

	return func(c *Client) error {
		//just set a pre-configured client if certificate validation should be skipped
		if insecureSkipVerify {
			transCfg := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
			}
			c.Client = &http.Client{
				Transport: transCfg,
			}
			log.Warn("[CONCLIENT] Skipping validation of TLS-Certificates of Connector API Endpoint.")
		} else {

			transCfg := &http.Transport{
				TLSClientConfig: &tls.Config{},
			}
			c.Client = &http.Client{
				Transport: transCfg,
			}
		}
		return nil
	}
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
	log.Trace("[ok] queried Connector Health Endpoint")
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
	result, err := c.Client.HealthcheckWithResponse(
		ctx)
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
	result, err := c.Client.GetOrganizationWithResponse(ctx, Orgparameter(orgName))
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
	result, err := c.Client.GetApiWithResponse(ctx, Orgparameter(orgName), ApiName(apiName), &params)
	if err != nil {
		return false, err
	}
	return result.StatusCode() == http.StatusOK, nil
}

// IsAPIProductAvailable - checks if there is already an API-Product existing
func (c *Access) IsAPIProductAvailable(orgName string, productName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.GetApiProductWithResponse(ctx, Orgparameter(orgName), ApiProductName(productName))
	if err != nil {
		return false, err
	}
	return result.StatusCode() == http.StatusOK, nil
}

// IsTeamAvailable - checks if there is already an API-Team existing
func (c *Access) IsTeamAvailable(orgName string, teamName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.GetTeamWithResponse(ctx, Orgparameter(orgName), TeamName(teamName))
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
	result, err := c.Client.GetTeamAppWithResponse(ctx, Orgparameter(orgName), TeamName(teamName), AppName(appName), &topicSyntax)
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
	listEnvironments, err := c.Client.ListEnvironmentsWithResponse(ctx, Orgparameter(orgName), &params)
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

// GetTeamApp - retrieves App as generic JSON
func (c *Access) GetTeamApp(orgName string, teamName string, appName string) (*SolaceCredentialsDto, map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	params := GetTeamAppParams{}
	result, err := c.Client.GetTeamAppWithResponse(ctx, Orgparameter(orgName), TeamName(teamName), AppName(appName), &params)
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT] [GetTeamApp] [GetTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] ", orgName, teamName, appName)
		return nil, nil, err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "GetTeamAppWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       "n/a",
		}
		log.Tracef("[FAULT] [CONCLIENT] [GetTeamApp] [GetTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] [%s]", orgName, teamName, appName, returnError.Error())
		return nil, nil, returnError
	}

	jsonMap := make(map[string]interface{})
	errMarshalling := json.Unmarshal(result.Body, &jsonMap)
	if errMarshalling != nil {
		return nil, nil, errMarshalling
	}
	credentialsDto := SolaceCredentialsDto{
		ConsumerKey:    result.JSON200.Credentials.Secret.ConsumerKey,
		ConsumerSecret: result.JSON200.Credentials.Secret.ConsumerSecret,
		IssuedAt:       result.JSON200.Credentials.IssuedAt,
		ExpiresAt:      &result.JSON200.Credentials.ExpiresAt,
	}
	return &credentialsDto, jsonMap, nil
}

// GetAppApiNames - retrieves AsyncAPI Names of app
func (c *Access) GetAppApiNames(orgName string, appName string) (*[]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	params := ListAppApiSpecificationsParams{}
	result, err := c.Client.ListAppApiSpecificationsWithResponse(ctx, Orgparameter(orgName), AppName(appName), &params)
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT] [GetAppApiNames] [ListAppApiSpecificationsWithResponse] [orgName:%s] [appName:%s] ", orgName, appName)
		return nil, err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "ListAppApiSpecificationsWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       "n/a",
		}
		log.Debugf("[FAULT] [CONCLIENT] [GetAppApiNames] [ListAppApiSpecificationsWithResponse] [orgName:%s] [appName:%s] [HTTP-CODE:%s] [Request:%s] [%s]", orgName, appName, result.StatusCode(), result.HTTPResponse.Request.URL, string(result.Body[:]))

		return nil, returnError
	}
	return result.JSON200, nil
}

func (c *Access) GetAppApiSpecification(orgName string, appName string, apiName string) (*map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	//todo add format parameter after bugfix of connector-api
	//format := GetAppApiSpecificationParamsFormat("application/json")
	params := &GetAppApiSpecificationParams{
		//Format: &format,
	}
	result, err := c.Client.GetAppApiSpecificationWithResponse(ctx, Orgparameter(orgName), AppName(appName), ApiName(apiName), params)
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT] [GetAppApiSpecification] [GetAppApiSpecificationWithResponse] [orgName:%s] [appName:%s] [apiName:%s] [%s]", orgName, appName, apiName, err)
		return nil, err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "GetAppApiSpecificationWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       "n/a",
		}
		log.Tracef("[FAULT] [CONCLIENT] [GetAppApiSpecification] [GetAppApiSpecificationWithResponse] [orgName:%s] [appName:%s] [apiName:%s] [HTTP-CODE:%s] [Request:%s] [%s]", orgName, appName, apiName, result.StatusCode(), result.HTTPResponse.Request.URL, string(result.Body[:]))
		return nil, returnError

	}
	return result.JSON200, nil
}

// RemoveTeamApp - removes the Team-Application
func (c *Access) RemoveTeamApp(orgName string, teamName string, appName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.DeleteTeamAppWithResponse(ctx, Orgparameter(orgName), TeamName(teamName), AppName(appName))
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT] [RemoveTeamApp] [DeleteTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] ", orgName, teamName, appName)
		return err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "DeleteTeamAppWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Tracef("[FAULT] [CONCLIENT] [RemoveTeamApp] [DeleteTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] [HTTP-CODE:%d] [Request:%s] [Response:%s]", orgName, teamName, appName, result.StatusCode(), result.HTTPResponse.Request.URL, string(result.Body[:]))
		return returnError
	}
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
	result, err := c.Client.CreateTeamAppWithResponse(ctx, Orgparameter(orgName), TeamName(teamName), payload)
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT] [PublishTeamApp] [CreateTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] [displayName:%s] [apiProducts:%s]", orgName, teamName, appName, displayName, strings.Join(apiProducts, ","))
		return nil, err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateTeamAppWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}

		log.Tracef("[FAULT] [CONCLIENT] [PublishTeamApp] [CreateTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] [displayName:%s] [apiProducts:%s] [HTTP-CODE:%s] [Request:%s] [%s]", orgName, teamName, appName, displayName, strings.Join(apiProducts, ","), result.StatusCode(), result.HTTPResponse.Request.URL, string(result.Body[:]))
		return nil, returnError
	}
	log.Tracef("[OK] [CONCLIENT] [PublishTeamApp] [CreateTeamAppWithResponse] [orgName:%s] [teamName:%s] [appName:%s] [displayName:%s] [apiProducts:%s]", orgName, teamName, appName, displayName, strings.Join(apiProducts, ","))

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
	result, err := c.Client.CreateTeamWithResponse(ctx, Orgparameter(orgName), CreateTeamJSONRequestBody(payload))
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT] [PublishTeam] [CreateTeamWithResponse] [orgName:%s] [teamName:%s]", orgName, teamName)
		return err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateTeamWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Tracef("[FAULT] [CONCLIENT] [PublishTeam] [CreateTeamWithResponse][orgName:%s] [teamName:%s] [HTTP-CODE:%s] [Request:%s] [%s]", orgName, teamName, result.StatusCode(), result.HTTPResponse.Request.RequestURI, returnError.Error())
		return returnError
	}
	log.Tracef("[OK] [CONCLIENT] [PublishTeam] [CreateTeamWithResponse][orgName:%s] [teamName:%s][%s]", orgName, teamName)
	return nil
}

// RemoveAPIProduct - removes Api-Product
func (c *Access) RemoveAPIProduct(orgName string, productName string, ignoreConflictResponse bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	result, err := c.Client.DeleteApiProductWithResponse(ctx, Orgparameter(orgName), ApiProductName(productName))
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT] [RemoveAPIProduct] [DeleteApiProductWithResponse] [orgName:%s] [productName:%s] ", orgName, productName, err.Error())
		return err
	}
	if ignoreConflictResponse {
		if result.StatusCode() == http.StatusConflict {
			log.Tracef("[INFO] [CONCLIENT] [RemoveAPIProduct] [DeleteApiProductWithResponse] [orgName:%s] [apiName:%s] [Tried to delete API-Product but still referenced] [HTTP-Status:%d] [Request:%s]", orgName, productName, result.StatusCode(), result.HTTPResponse.Request.RequestURI, result.StatusCode())
			return nil
		}
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "DeleteApiProductWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Tracef("[FAULT] [CONCLIENT] [RemoveAPIProduct] [DeleteApiProductWithResponse] [orgName:%s]  [productName:%s] [HTTP-CODE:%s] [Request:%s] [%s]", orgName, productName, result.StatusCode(), result.HTTPResponse.Request.URL, string(result.Body[:]))
		return returnError
	}
	log.Tracef("[OK] [CONCLIENT] [RemoveAPIProduct] [orgName:%s]  [productName:%s]  [%s]", orgName, productName)
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
	result, err := c.Client.CreateApiProductWithResponse(ctx, Orgparameter(orgName), CreateApiProductJSONRequestBody(payload))
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT] [PublishAPIProduct] [CreateApiProductWithResponse] [orgName:%s] [productName:%s] [apiNames:%s] [environments:%s] [protocols:%s]", orgName, productName, strings.Join(apiNames, ","), strings.Join(environments, ","), strings.Join(protocolsToString(protocols), ","))
		return err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateApiProductWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Tracef("[FAULT] [CONCLIENT] [PublishAPIProduct] [CreateApiProductWithResponse] [orgName:%s] [productName:%s] [apiNames:%s] [environments:%s] [protocols:%s] [HTTP-Status:%d] [Request:%s] [%s]", orgName, productName, strings.Join(apiNames, ","), strings.Join(environments, ","), strings.Join(protocolsToString(protocols), ","), result.StatusCode(), result.HTTPResponse.Request.URL, string(result.Body[:]))
		return returnError
	}
	log.Tracef("[OK] [CONCLIENT] [PublishAPIProduct] [CreateApiProductWithResponse]  [Http-Status:%d] [orgName:%s] [productName:%s] [apiNames:%s] [environments:%s] [protocols:%s]", result.StatusCode(), orgName, productName, strings.Join(apiNames, ","), strings.Join(environments, ","), strings.Join(protocolsToString(protocols), ","))
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

	result, err := c.Client.DeleteApiWithResponse(ctx, Orgparameter(orgName), ApiName(apiName))
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT] [RemoveAPI] [DeleteApiWithResponse] [orgName:%s] [apiName:%s] ", orgName, apiName, err.Error())
		return err
	}
	if ignoreConflictResponse {
		if result.StatusCode() == http.StatusConflict {
			log.Tracef("[INFO] [CONCLIENT] [RemoveAPI] [DeleteApiWithResponse] [orgName:%s] [apiName:%s] [Tried to delete API but still referenced] [HTTP-Status:%d] ", orgName, apiName, result.StatusCode())
			return nil
		}
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "DeleteApiWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Tracef("[FAULT] [CONCLIENT] [RemoveAPI] [DeleteApiWithResponse] [orgName:%s] [apiName:%s]  [HTTP-Status:%d] [Request:%s]  [%s]", orgName, apiName, result.StatusCode(), result.HTTPResponse.Request.URL, string(result.Body[:]))
		return returnError
	}
	log.Tracef("[OK] [CONCLIENT] [RemoveAPI] [DeleteApiWithResponse] [Http-Status:%d] [orgName:%s] [apiName:%s]  ", result.StatusCode(), orgName, apiName)
	return nil
}

// PublishAPI - publishes API
func (c *Access) PublishAPI(orgName string, apiName string, apiSpec []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	result, err := c.Client.CreateApiWithBodyWithResponse(ctx, Orgparameter(orgName), ApiName(apiName), "text/plain", bytes.NewReader(apiSpec))
	if err != nil {
		log.Tracef("[ERROR] [CONCLIENT] [PublishAPI] [CreateApiWithBodyWithResponse] [orgName:%s] [apiName:%s] [apiSpec-length:%d] [%s]", orgName, apiName, len(apiSpec), err.Error())
		return err
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateApiWithBodyWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		log.Tracef("[FAULT] [CONCLIENT] [PublishAPI] [CreateApiWithBodyWithResponse]  [orgName:%s] [apiName:%s] [apiSpec-length:%d] [HTTP-Status:%d] [Request:%s] [%s]", orgName, apiName, len(apiSpec), result.StatusCode(), result.HTTPResponse.Request.URL, string(result.Body[:]))
		return returnError
	}
	log.Tracef("[OK] [CONCLIENT] [PublishAPI] [CreateApiWithBodyWithResponse]  [Http-Status:%d] [orgName:%s] [apiName:%s] [apiSpec-length:%d] ", result.StatusCode(), orgName, apiName, len(apiSpec))
	return nil
}
