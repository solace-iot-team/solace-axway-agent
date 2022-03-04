package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/Axway/agent-sdk/pkg/util"
	hc "github.com/Axway/agent-sdk/pkg/util/healthcheck"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/pkg/errors"
	"github.com/solace-iot-team/solace-axway-agent/pkg/config"
	"github.com/solace-iot-team/solace-axway-agent/pkg/solace"
	"io"
	"net"
	"net/http"
	"net/url"
	url2 "net/url"
	"os"
	"time"
)

const connectorName = "Solace Connector"

// ConClientResponse  - Raw response of Connector
type ConClientResponse interface {
	Body() []byte
	HTTPResponse() *http.Response
}

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

// SolaceEnvironmentEndpoint Holds details of messaging protocol in an solace environment
type SolaceEnvironmentEndpoint struct {
	ProtocolName    string
	ProtocolVersion string
	Compressed      string
	Secure          string
	Transport       string
	Uri             string
}

// SolaceEnvironment Holds connection details for Solacce VPN Environment
type SolaceEnvironment struct {
	Name            string
	ServiceID       string
	Host            string
	ProtocolVersion map[string]string
}

// SolaceCredentialsDto - Credentials of App
type SolaceCredentialsDto struct {
	ConsumerKey    string
	ConsumerSecret *string
	IssuedAt       *int64
	ExpiresAt      *int64
}

type connectorClients struct {
	AdminConnector *Access
	OrgConnector   *Access
}

// Access Holds refernce to HTTP-Client to Solace Connector
type Access struct {
	Client    *ClientWithResponses
	LogBody   bool
	LogHeader bool
}

// Attribute Solace Connector Attribute
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SolaceWebhook Solace Webhook
type SolaceWebhook struct {
	HTTPMethod               string
	CallbackURL              string
	AuthenticationMethod     string
	AuthenticationIdentifier string
	AuthenticationSecret     string
	InvocationOrder          string
	TrusedCNs                []string
}

// GetWebHookAuth - Creates a WebHookAuth structure
func (s *SolaceWebhook) GetWebHookAuth() *WebHookAuth {
	var result WebHookAuth = nil
	switch s.AuthenticationMethod {
	case solace.SolaceAuthenticationMethodNoAuthentication:
		return nil
	case solace.SolaceAuthenticationMethodBasicAuthentication:
		var method WebHookBasicAuthAuthMethod = WebHookBasicAuthAuthMethodBasic
		result = WebHookBasicAuth{
			AuthMethod: &method,
			Username:   CommonUserName(s.AuthenticationIdentifier),
			Password:   s.AuthenticationSecret,
		}
	case solace.SolaceAuthenticationMethodHTTPHeaderAuthentication:
		var method WebHookHeaderAuthAuthMethod = WebHookHeaderAuthAuthMethodHeader
		result = WebHookHeaderAuth{
			AuthMethod:  &method,
			HeaderName:  s.AuthenticationIdentifier,
			HeaderValue: s.AuthenticationSecret,
		}
	default:
		log.Warn("Unsupported Solace Callback Authentication Method: %s", s.AuthenticationMethod)
		return nil
	}

	return &result
}

// GetWebHookMethod - Creates WebHookMethod
func (s *SolaceWebhook) GetWebHookMethod() WebHookMethod {
	if s.HTTPMethod == solace.SolaceHTTPMethodPut {
		return WebHookMethodPUT
	}
	return WebHookMethodPOST
}

// GetMode - Returns either Parallel or Serial
func (s *SolaceWebhook) GetMode() *WebHookMode {
	if s.InvocationOrder == solace.SolaceInvocationOrderParallel {
		result := WebHookModeParallel
		return &result
	}
	result := WebHookModeSerial
	return &result
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
		Client:    orgClient,
		LogBody:   gatewayCfg.ConnectorLogBody,
		LogHeader: gatewayCfg.ConnectorLogHeader,
	}
	connectors.AdminConnector = &Access{
		Client:    adminClient,
		LogBody:   gatewayCfg.ConnectorLogBody,
		LogHeader: gatewayCfg.ConnectorLogHeader,
	}

	//register HealthChecker
	hc.RegisterHealthcheck(connectorName, "solace", connectors.AdminConnector.Healthcheck)

	return nil
}

// NewConnectorAdminClient - Creates a new Gateway Client
func NewConnectorAdminClient(gatewayCfg *config.ConnectorConfig) (*ClientWithResponses, error) {
	timeout := getTimeoutFromEnvironment()
	basicAuthProvider, basicAuthProviderErr := securityprovider.NewSecurityProviderBasicAuth(gatewayCfg.ConnectorAdminUser, gatewayCfg.ConnectorAdminPassword)
	if basicAuthProviderErr != nil {
		panic(basicAuthProviderErr)
	}
	myclient, err := NewClientWithResponses(gatewayCfg.ConnectorURL, WithTLSConfig(gatewayCfg.ConnectorInsecureSkipVerify, gatewayCfg.ConnectorProxyURL, timeout), WithRequestEditorFn(basicAuthProvider.Intercept))
	if err != nil {
		return nil, err
	}
	return myclient, nil
}

// NewConnectorOrgClient - Creates a new Gateway Client
func NewConnectorOrgClient(gatewayCfg *config.ConnectorConfig) (*ClientWithResponses, error) {
	timeout := getTimeoutFromEnvironment()
	basicAuthProvider, basicAuthProviderErr := securityprovider.NewSecurityProviderBasicAuth(gatewayCfg.ConnectorOrgUser, gatewayCfg.ConnectorOrgPassword)
	if basicAuthProviderErr != nil {
		panic(basicAuthProviderErr)
	}
	myclient, err := NewClientWithResponses(gatewayCfg.ConnectorURL, WithTLSConfig(gatewayCfg.ConnectorInsecureSkipVerify, gatewayCfg.ConnectorProxyURL, timeout), WithRequestEditorFn(basicAuthProvider.Intercept))
	if err != nil {
		return nil, err
	}
	return myclient, nil
}

// WithTLSConfig - Creates ClientOption
func WithTLSConfig(insecureSkipVerify bool, proxyURL string, timeout time.Duration) ClientOption {

	return func(c *Client) error {

		url, err := url.Parse(proxyURL)
		if err != nil {
			log.Errorf("Error parsing proxyURL from config (connector.proxyUrl); creating a non-proxy client: %s", err.Error())
		}

		//just set a pre-configured client if certificate validation should be skipped
		if insecureSkipVerify {
			transCfg := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
				Proxy:           util.GetProxyURL(url),
			}
			c.Client = &http.Client{
				Timeout:   timeout,
				Transport: transCfg,
			}
			log.Warn("[CONCLIENT] Skipping validation of TLS-Certificates of Connector API Endpoint.")
		} else {
			transCfg := &http.Transport{
				TLSClientConfig: &tls.Config{},
				Proxy:           util.GetProxyURL(url),
			}
			c.Client = &http.Client{
				Timeout:   timeout,
				Transport: transCfg,
			}
		}
		return nil
	}
}

// borrowed from Axway/agent-sdk api/client.go
func getTimeoutFromEnvironment() time.Duration {
	defaultTimeout := time.Second * 60

	cfgHTTPClientTimeout := os.Getenv("HTTP_CLIENT_TIMEOUT")
	if cfgHTTPClientTimeout == "" {
		return defaultTimeout
	}
	timeout, err := time.ParseDuration(cfgHTTPClientTimeout)
	if err != nil {
		log.Tracef("Unable to parse the HTTP_CLIENT_TIMEOUT value, using the default http client timeout")
		return defaultTimeout
	}
	return timeout
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
		log.Tracef("[CONCLIENT] [IsHealthCheck] [err:%s]", err)
		return false, err
	}
	log.Tracef("[CONCLIENT] [IsHealthCheck]  %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
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
		log.Tracef("[CONCLIENT] [IsOrgRegistered] [err:%s]", err)
		return false, err
	}
	log.Tracef("[CONCLIENT] [IsOrgRegistered]  %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	return result.StatusCode() == http.StatusOK, nil
}

// DeleteOrg - deletes an entire Organization in the connector. Make sure you exactly know what you are doing
func (c *Access) DeleteOrg(orgName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.DeleteOrganizationWithResponse(ctx, Orgparameter(orgName))
	if err != nil {
		return false, err
	}
	log.Tracef("[CONCLIENT] [DeleteOrg] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	return result.StatusCode() < 300, nil
}

// CreateOrg - creates an Org
func (c *Access) CreateOrg(orgName string, token *interface{}) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	body := CreateOrganizationJSONRequestBody{
		Name:       CommonName(orgName),
		CloudToken: token,
	}
	result, err := c.Client.CreateOrganizationWithResponse(ctx, body)
	if err != nil {
		log.Tracef("[CONCLIENT] [CreateOrg] [err:%s]", err)
		return false, err
	}
	log.Tracef("[CONCLIENT] [CreateOrg] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	return result.StatusCode() < 300, nil
}

// IsAPIAvailable - checks if there is already an API existing
func (c *Access) IsAPIAvailable(orgName string, apiName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	params := GetApiParams{}
	result, err := c.Client.GetApiWithResponse(ctx, Orgparameter(orgName), ApiName(apiName), &params)
	if err != nil {
		log.Tracef("[CONCLIENT] [IsAPIAvailable] [err:%s]", err)
		return false, err
	}
	log.Tracef("[CONCLIENT] [IsAPIAvailable] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	return result.StatusCode() == http.StatusOK, nil
}

// IsAPIProductAvailable - checks if there is already an API-Product existing
func (c *Access) IsAPIProductAvailable(orgName string, productName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.GetApiProductWithResponse(ctx, Orgparameter(orgName), ApiProductName(productName))
	if err != nil {
		log.Tracef("[CONCLIENT] [IsAPIProductAvailable] [err:%s]", err)
		return false, err
	}
	log.Tracef("[CONCLIENT] [IsAPIProductAvailable] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	return result.StatusCode() == http.StatusOK, nil
}

// IsTeamAvailable - checks if there is already an API-Team existing
func (c *Access) IsTeamAvailable(orgName string, teamName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.GetTeamWithResponse(ctx, Orgparameter(orgName), TeamName(teamName))
	if err != nil {
		log.Tracef("[CONCLIENT] [IsTeamAvailable] [err:%s]", err)
		return false, err
	}
	log.Tracef("[CONCLIENT] [IsTeamAvailable] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
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
		log.Tracef("[CONCLIENT] [IsTeamAppAvailable] [err:%s]", err)
		return false, err
	}
	log.Tracef("[CONCLIENT] [IsTeamAppAvailable] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	return result.StatusCode() == http.StatusOK, nil
}

// CreateEnvironment - creates new Environment
func (c *Access) CreateEnvironment(orgName string, envName string, description string, serviceID string, protocolVersions []map[string]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	props := make(map[string]interface{}, 0)
	displayName := CommonDisplayName(envName)
	protocols := make([]Protocol, 0)
	for _, pv := range protocolVersions {
		version := CommonVersion(pv["version"])
		p := Protocol{
			Name:    ProtocolName(pv["name"]),
			Version: &version,
		}
		protocols = append(append(protocols, p))
	}
	environment := Environment{
		Name:                 CommonName(envName),
		Description:          CommonDescription("Environment for Integration Tests - will get removed"),
		DisplayName:          &displayName,
		ExposedProtocols:     protocols,
		ServiceId:            serviceID,
		AdditionalProperties: props,
	}

	result, err := c.Client.CreateEnvironmentWithResponse(ctx, Orgparameter(orgName), CreateEnvironmentJSONRequestBody(environment))
	if err != nil {
		log.Tracef("[CONCLIENT] [CreateEnvironment] [err:%s]", err)
		return err
	}
	log.Tracef("[CONCLIENT] [CreateEnvironment] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if result.StatusCode() < 300 {
		return nil
	}
	return errors.New("CreateEnvironment was not successful")

}

// DeleteEnvironment - Deletes Environment
func (c *Access) DeleteEnvironment(orgName string, envName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.DeleteEnvironment(ctx, Orgparameter(orgName), EnvName(envName))
	if err != nil {
		log.Tracef("[CONCLIENT] [DeleteEnvironment] [err:%s]", err)
		return false, err
	}
	log.Tracef("[CONCLIENT] [DeleteEnvironment] %s", c.logTextHTTPResponse([]byte("NO BODY"), result))
	return result.StatusCode < 300, nil

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
		log.Tracef("[CONCLIENT] [GetListEnvironments] [err:%s]", err)
		return nil, err
	}
	if listEnvironments.StatusCode() != http.StatusOK {
		return nil, errors.New("Solace-Connector did not return HTTP-200 for listEnvironments")
	}
	log.Tracef("[CONCLIENT] [GetListEnvironments] %s", c.logTextHTTPResponse(listEnvironments.Body, listEnvironments.HTTPResponse))
	solaceEnvs := make([]SolaceEnvironment, 0)
	for _, env := range *listEnvironments.JSON200 {
		host, _ := deriveHostFromProtocols(env)
		//todo log error for debugging / follow up in logs

		solaceEnvs = append(solaceEnvs, SolaceEnvironment{
			Name:            DerefString((*string)(env.Name)),
			ServiceID:       DerefString(env.ServiceId),
			Host:            host,
			ProtocolVersion: extractProtocolVersionMap(env)})
	}
	return solaceEnvs, nil
}

// GetEnvironmentEndpoints - provides a list of all endpoints of an environment
func (c *Access) GetEnvironmentEndpoints(orgName string, envName string) ([]SolaceEnvironmentEndpoint, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	solaceEnvMps := make([]SolaceEnvironmentEndpoint, 0)
	envResponse, err := c.Client.GetEnvironmentWithResponse(ctx, Orgparameter(orgName), EnvName(envName))
	if err != nil {
		log.Tracef("[CONCLIENT] [GetEnvironment] [err:%s]", err)
		return nil, err
	}
	if envResponse.StatusCode() != http.StatusOK {
		return nil, errors.New("Solace-Connector did not return HTTP-200 for GetEnvironmentWithResponse")
	}
	for _, ep := range *envResponse.JSON200.MessagingProtocols {
		solaceEnvMps = append(solaceEnvMps, SolaceEnvironmentEndpoint{
			ProtocolName:    fmt.Sprint(ep.Protocol.Name),
			ProtocolVersion: fmt.Sprint(ep.Protocol.Version),
			Compressed:      fmt.Sprint(ep.Compressed),
			Secure:          fmt.Sprint(ep.Secure),
			Transport:       DerefString(ep.Transport),
			Uri:             DerefString(ep.Uri),
		})
	}
	return solaceEnvMps, nil
}

func extractProtocolVersionMap(env EnvironmentListItem) map[string]string {
	protocolVersionMap := make(map[string]string)
	for _, endpoint := range *env.ExposedProtocols {
		protocolVersionMap[string(endpoint.Name)] = string(*endpoint.Version)
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
		log.Tracef("[CONCLIENT] [GetTeamApp] [err:%s]", err)
		return nil, nil, err
	}
	log.Tracef("[CONCLIENT] [GetTeamApp] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
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
		IssuedAt:       (*int64)(result.JSON200.Credentials.IssuedAt),
		ExpiresAt:      &result.JSON200.Credentials.ExpiresAt,
	}
	return &credentialsDto, jsonMap, nil
}

// GetAppAPINames - retrieves AsyncAPI Names of app
func (c *Access) GetAppAPINames(orgName string, appName string) (*[]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	params := ListAppApiSpecificationsParams{}
	result, err := c.Client.ListAppApiSpecificationsWithResponse(ctx, Orgparameter(orgName), AppName(appName), &params)
	if err != nil {
		log.Tracef("[CONCLIENT] [GetAppAPINames] [err:%s]", err)
		return nil, err
	}
	log.Tracef("[CONCLIENT] [GetAppAPINames] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "ListAppApiSpecificationsWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       "n/a",
		}
		return nil, returnError
	}
	return result.JSON200, nil
}

// GetAppAPISpecification - Queries Application API Specification as raw JSON
func (c *Access) GetAppAPISpecification(orgName string, appName string, apiName string) (*map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	//todo add format parameter after bugfix of connector-api
	//format := GetAppApiSpecificationParamsFormat("application/json")
	params := &GetAppApiSpecificationParams{
		//Format: &format,
	}
	result, err := c.Client.GetAppApiSpecificationWithResponse(ctx, Orgparameter(orgName), AppName(appName), ApiName(apiName), params)
	if err != nil {
		log.Tracef("[CONCLIENT] [GetAppAPISpecification] [err:%s]", err)
		return nil, err
	}
	log.Tracef("[CONCLIENT] [GetAppAPISpecification] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "GetAppApiSpecificationWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       "n/a",
		}
		return nil, returnError
	}
	return &result.JSON200.AdditionalProperties, nil
}

// RemoveTeamApp - removes the Team-Application
func (c *Access) RemoveTeamApp(orgName string, teamName string, appName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	result, err := c.Client.DeleteTeamAppWithResponse(ctx, Orgparameter(orgName), TeamName(teamName), AppName(appName))
	if err != nil {
		log.Tracef("[CONCLIENT] [RemoveTeamApp] [err:%s]", err)
		return err
	}
	log.Tracef("[CONCLIENT] [RemoveTeamApp] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "DeleteTeamAppWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		return returnError
	}
	return nil
}

// PublishTeamApp - publishes TeamApp
func (c *Access) PublishTeamApp(orgName string, teamName string, appName string, displayName string, apiProducts []string, solaceWebhook *SolaceWebhook, appAttributes map[string]string) (*Credentials, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	credentials := Credentials{
		ExpiresAt: -1,
		IssuedAt:  nil,
		Secret:    nil,
	}

	connectorAppAttributes := Attributes{}
	for k, v := range appAttributes {
		connectorAppAttributes = append(connectorAppAttributes, struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}{Name: k, Value: v})
	}

	commonNames := make([]CommonName, len(apiProducts))
	for i := range apiProducts {
		commonNames[i] = CommonName(apiProducts[i])
	}
	var webhooks []WebHook = nil
	var payload CreateTeamAppJSONRequestBody
	var tlsOptions *WebHookTLSOptions = nil
	if solaceWebhook != nil {
		if len(solaceWebhook.TrusedCNs) > 0 {
			tlsOptions = &WebHookTLSOptions{
				TlsTrustedCommonNames: &solaceWebhook.TrusedCNs,
			}
		}
		webhoock := WebHook{
			Authentication: solaceWebhook.GetWebHookAuth(),
			//all environments
			Method:     solaceWebhook.GetWebHookMethod(),
			Mode:       solaceWebhook.GetMode(),
			Uri:        solaceWebhook.CallbackURL,
			TlsOptions: tlsOptions,
		}
		webhooks = append(webhooks, webhoock)
		payload = CreateTeamAppJSONRequestBody{
			Name:        CommonName(appName),
			DisplayName: (*CommonDisplayName)(&displayName),
			ApiProducts: commonNames,
			Credentials: credentials,
			WebHooks:    &webhooks,
			Attributes:  &connectorAppAttributes,
		}
	} else {
		payload = CreateTeamAppJSONRequestBody{
			Name:        CommonName(appName),
			DisplayName: (*CommonDisplayName)(&displayName),
			ApiProducts: commonNames,
			Credentials: credentials,
			Attributes:  &connectorAppAttributes,
		}
	}

	result, err := c.Client.CreateTeamAppWithResponse(ctx, Orgparameter(orgName), TeamName(teamName), payload)
	if err != nil {
		log.Tracef("[CONCLIENT] [PublishTeamApp] [err:%s]", err)
		return nil, err
	}
	log.Tracef("[CONCLIENT] [CreateTeamAppWithResponse] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateTeamAppWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}

		return nil, returnError
	}
	return &result.JSON201.Credentials, nil
}

// DeleteTeam - deletes a team
func (c *Access) DeleteTeam(orgName string, teamName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	result, err := c.Client.DeleteTeamWithResponse(ctx, Orgparameter(orgName), TeamName(teamName))
	if err != nil {
		log.Tracef("[CONCLIENT] [DeleteTeam] [err:%s]", err)
		return err
	}
	log.Tracef("[CONCLIENT] [DeleteTeam] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "DeleteTeam",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}

		return returnError
	}
	return nil
}

// PublishTeam - publishes / creates a team
func (c *Access) PublishTeam(orgName string, teamName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	payload := CreateTeamJSONBody{
		Name:        CommonName(teamName),
		DisplayName: CommonDisplayName(teamName),
	}
	result, err := c.Client.CreateTeamWithResponse(ctx, Orgparameter(orgName), CreateTeamJSONRequestBody(payload))
	if err != nil {
		log.Tracef("[CONCLIENT] [PublishTeam] [err:%s]", err)
		return err
	}
	log.Tracef("[CONCLIENT] [PublishTeam] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateTeamWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		return returnError
	}
	return nil
}

// RemoveAPIProduct - removes API-Product
func (c *Access) RemoveAPIProduct(orgName string, productName string, ignoreConflictResponse bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	result, err := c.Client.DeleteApiProductWithResponse(ctx, Orgparameter(orgName), ApiProductName(productName))
	if err != nil {
		log.Tracef("[CONCLIENT] [RemoveAPIProduct] [err:%s]", err)
		return err
	}
	log.Tracef("[CONCLIENT] [RemoveAPIProduct] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if ignoreConflictResponse {
		if result.StatusCode() == http.StatusConflict {
			return nil
		}
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "DeleteApiProductWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		return returnError
	}
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
	commonNames := make([]CommonName, len(apiNames))
	for i := range apiNames {
		commonNames[i] = CommonName(apiNames[i])
	}
	commonNamesEnvironments := make([]CommonName, len(environments))
	for i := range environments {
		commonNamesEnvironments[i] = CommonName(environments[i])
	}
	desc := CommonDescription(d)
	payload := CreateApiProductJSONRequestBody{
		Name:         CommonName(productName),
		Apis:         commonNames,
		ApprovalType: &a,
		Description:  &desc,
		DisplayName:  CommonDisplayName(productName),
		Environments: &commonNamesEnvironments,
		Protocols:    &protocols,
		PubResources: make([]CommonTopic, 0),
		SubResources: make([]CommonTopic, 0),
		Attributes:   attributes,
	}
	result, err := c.Client.CreateApiProductWithResponse(ctx, Orgparameter(orgName), CreateApiProductJSONRequestBody(payload))
	if err != nil {
		log.Tracef("[CONCLIENT] [PublishAPIProduct] [err:%s]", err)
		return err
	}
	log.Tracef("[CONCLIENT] [PublishAPIProduct] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateApiProductWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		return returnError
	}
	return nil
}

func protocolsToString(protocols []Protocol) []string {
	result := make([]string, 0)
	for _, item := range protocols {
		text := string(item.Name)
		if item.Version != nil {
			text = text + ":" + string(*item.Version)
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
		log.Tracef("[CONCLIENT] [RemoveAPI] [err:%s]", err)
		return err
	}
	log.Tracef("[CONCLIENT] [RemoveAPI] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if ignoreConflictResponse {
		if result.StatusCode() == http.StatusConflict {
			return nil
		}
	}
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "DeleteApiWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		return returnError
	}
	return nil
}

// PublishAPI - publishes API
func (c *Access) PublishAPI(orgName string, apiName string, apiSpec []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()

	result, err := c.Client.CreateApiWithBodyWithResponse(ctx, Orgparameter(orgName), ApiName(apiName), "text/plain", bytes.NewReader(apiSpec))
	if err != nil {
		log.Tracef("[CONCLIENT] [PublishAPI] [err:%s]", err)
		return err
	}
	log.Tracef("[CONCLIENT] [PublishAPI] %s", c.logTextHTTPResponse(result.Body, result.HTTPResponse))
	if result.StatusCode() >= 300 {
		returnError := &ConclientHTTPError{
			ClientFunction: "CreateApiWithBodyWithResponse",
			HTTPStatusCode: int(result.StatusCode()),
			Response:       string(result.Body[:]),
		}
		return returnError
	}
	return nil
}

// DerefString - dereferences String pointer and returns empty string for NIL
func DerefString(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}

func (c *Access) logTextHTTPResponse(body []byte, response *http.Response) string {
	requestURL := "NIL"
	requestBody := "NIL"
	responseBody := "NIL"
	requestVerb := "NIL"
	requestHeader := "NIL"
	if response.Request != nil {
		if response.Request.URL != nil {
			requestURL = response.Request.URL.String()
			requestVerb = response.Request.Method
			if c.LogHeader {
				requestHeader = mapToString(response.Request.Header)
			} else {
				requestHeader = "***"
			}
		}

		if c.LogBody {
			requestBody = readToString(response.Request.Body)
			if body != nil {
				responseBody = string(body)
			}
		} else {
			requestBody = "***"
			responseBody = "***"
		}
	}
	return fmt.Sprintf("[HTTP-Code:%d] [Request-URL:%s] [Request-Verb:%s] [Request-Header:%s] [Request-Body:%s] [Response-Body:%s]", response.StatusCode, requestURL, requestVerb, requestHeader, requestBody, responseBody)
}

func mapToString(m map[string][]string) string {
	b := new(bytes.Buffer)
	for key, value := range m {
		headerValue := new(bytes.Buffer)
		for _, headerValueItem := range value {
			fmt.Fprintf(headerValue, "%s ", headerValueItem)
		}
		fmt.Fprintf(b, "%s=\"%s\"", key, headerValue.String())
	}
	return b.String()
}

func readToString(reader io.ReadCloser) string {
	if reader == nil {
		return "NIL"
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(reader)
	return buf.String()
}
