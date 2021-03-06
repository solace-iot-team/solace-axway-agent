package notification

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/Axway/agent-sdk/pkg/util"
	hc "github.com/Axway/agent-sdk/pkg/util/healthcheck"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	"github.com/solace-iot-team/solace-axway-agent/pkg/config"
	"net/http"
	"net/url"
	"os"
	"time"
)

// ConclientHTTPError - Detailed HTTP-Error
type ConclientHTTPError struct {
	ClientFunction string
	HTTPStatusCode int
	Response       string
}

// SubscribeMetaDataDto - Metadata about Subscriber
type SubscribeMetaDataDto struct {
	API             string
	Application     string
	Environment     string
	Product         string
	Subscriber      string
	Subscriberemail string
	Subscription    string
	Team            string
	ApplicationData map[string]interface{}
	APISpecs        []*map[string]interface{}
}

// UnsubscribeMetaDataDto - Metadata about Subscriber
type UnsubscribeMetaDataDto struct {
	API             string
	Application     string
	Environment     string
	Product         string
	Subscriber      string
	Subscriberemail string
	Subscription    string
	Team            string
}

// MonitorDataDto - DTO for monitor notifications
type MonitorDataDto struct {
	Trigger         MonitorDataTrigger
	Success         bool
	Message         *string
	CorrelationID   string
	API             string
	Application     string
	Environment     string
	Product         string
	Subscriber      string
	Subscriberemail string
	Subscription    string
	Team            string
}

var message = "DEFAULT MESSAGE"

// Error - Created detailed HTTP-Error
func (c *ConclientHTTPError) Error() string {
	return fmt.Sprintf("Call [%s] was not successfull. [Http-Status:%d] [Response:%s]", c.ClientFunction, c.HTTPStatusCode, c.Response)
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

var notifierClient *Access

//Initialize sets connector client as admin and as org-admin
func Initialize(notifierCfg *config.NotifierConfig) error {
	message = notifierCfg.NotifierHealthMessage
	client, err := NewNotificationClient(notifierCfg)
	if err != nil {
		return err
	}

	notifierClient = &Access{
		Client: client,
	}

	//register HealthChecker
	hc.RegisterHealthcheck("Solace Subscription Notifier", "notifier", notifierClient.Healthcheck)
	return nil
}

// NewNotificationClient - Creates a new Gateway Client
func NewNotificationClient(notifierCfg *config.NotifierConfig) (*ClientWithResponses, error) {
	timeout := getTimeoutFromEnvironment()
	if notifierCfg.NotifierAAPIAuthType == "header" {
		authProvider, authErr := securityprovider.NewSecurityProviderApiKey("header", notifierCfg.NotifierAPIConsumerKey, notifierCfg.NotifierAPIConsumerSecret)
		if authErr != nil {
			panic(authErr)
		}
		myclient, err := NewClientWithResponses(notifierCfg.NotifierURL, WithRequestEditorFn(authProvider.Intercept), WithTlSConfig(notifierCfg.NotifierInsecureSkipVerify, notifierCfg.NotifierProxyURL, timeout))
		if err != nil {
			return nil, err
		}
		return myclient, nil
	} else if notifierCfg.NotifierAAPIAuthType == "basic" {
		authProvider, authErr := securityprovider.NewSecurityProviderBasicAuth(notifierCfg.NotifierAPIConsumerKey, notifierCfg.NotifierAPIConsumerSecret)
		if authErr != nil {
			panic(authErr)
		}
		myclient, err := NewClientWithResponses(notifierCfg.NotifierURL, WithRequestEditorFn(authProvider.Intercept), WithTlSConfig(notifierCfg.NotifierInsecureSkipVerify, notifierCfg.NotifierProxyURL, timeout))
		if err != nil {
			return nil, err
		}
		return myclient, nil
	}
	//safety
	panic(errors.New("Illegal NotifierAuthType:" + notifierCfg.NotifierAAPIAuthType))
}

// WithTlSConfig prepares TSLConfig
func WithTlSConfig(insecureSkipVerify bool, proxyURL string, timeout time.Duration) ClientOption {

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
				Transport: transCfg,
				Timeout:   timeout,
			}
			log.Warn("Skipping validation of TLS-Certificates of Notifier API Endpoint.")
		} else {

			transCfg := &http.Transport{
				TLSClientConfig: &tls.Config{},
				Proxy:           util.GetProxyURL(url),
			}
			c.Client = &http.Client{
				Transport: transCfg,
				Timeout:   timeout,
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

// GetNotifierClient - connector as admin
func GetNotifierClient() *Access {
	return notifierClient
}

func defaultTimeout() time.Duration {
	return 30 * time.Second
}

// Healthcheck - verify connection to Solace connector
func (c *Access) Healthcheck(name string) *hc.Status {
	// Set a default response
	log.Trace("[BEGIN] Triggered Health Check Message to Notification Endpoint")
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
		return &s
	}
	log.Trace("[OK] Posted Health Check Message to Notification Endpoint")
	return &s
}

// IsHealthCheck - checks if Connector is accessible as admin
func (c *Access) IsHealthCheck() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	body := PostHealthJSONRequestBody{Echo: "Health Check Ping [" + time.Now().Format(time.RFC3339) + "] [" + message + "]"}
	result, err := c.Client.PostHealthWithResponse(ctx, body)
	if err != nil {
		return false, err
	}
	if result.StatusCode() != http.StatusOK {
		return false, fmt.Errorf("Solace-Connector is accessible but returned HTTP-Status-Code: %v", result.StatusCode())
	}
	return result.StatusCode() == http.StatusOK, nil
}

// NotifySubscribe - publishes Subscribe Notification
func (c *Access) NotifySubscribe(dto SubscribeMetaDataDto) (bool, error) {
	//if there is no client, it is disabled
	if c == nil {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	body := PostSubscribeJSONRequestBody{
		Data: SubscribeData{
			Api:             dto.API,
			Application:     dto.Application,
			Environment:     dto.Environment,
			Product:         dto.Product,
			Subscriber:      dto.Subscriber,
			SubscriberEmail: dto.Subscriberemail,
			Subscription:    dto.Subscription,
			Team:            dto.Team,
			ApplicationData: dto.ApplicationData,
			AsyncApis:       dto.APISpecs,
		},
		Datacontenttype: "application/json",
		Id:              uuid.New().String(),
		Source:          "axway-solace-agent",
		Specversion:     "1.0",
		Time:            time.Now().Format(time.RFC3339),
		Type:            "com.solace.iot-team.asyncapi.notification.subscribe.v1",
	}
	result, err := c.Client.PostSubscribeWithResponse(ctx, body)
	if err != nil {
		return false, err
	}
	if result.StatusCode() >= 300 {
		return false, errors.New("Posting notification to Endpoint returned HTTP:" + result.Status())
	}
	return result.StatusCode() == http.StatusOK, nil
}

// NotifyUnsubscribe - publishes Unsubscribe Notifications
func (c *Access) NotifyUnsubscribe(dto UnsubscribeMetaDataDto) (bool, error) {
	//if there is no client, it is disabled
	if c == nil {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	body := PostUnsubscribeJSONRequestBody{
		Data: UnsubscribeData{
			Api:             dto.API,
			Application:     dto.Application,
			Environment:     dto.Environment,
			Product:         dto.Product,
			Subscriber:      dto.Subscriber,
			SubscriberEmail: dto.Subscriberemail,
			Subscription:    dto.Subscription,
			Team:            dto.Team,
		},
		Datacontenttype: "application/json",
		Id:              uuid.New().String(),
		Source:          "axway-solace-agent",
		Specversion:     "1.0",
		Time:            time.Now().Format(time.RFC3339),
		Type:            "com.solace.iot-team.asyncapi.notification.unsubscribe.v1",
	}
	result, err := c.Client.PostUnsubscribeWithResponse(ctx, body)
	if err != nil {
		return false, err
	}
	if result.StatusCode() >= 300 {
		return false, errors.New("Posting unsubscribe notification to Endpoint returned HTTP:" + result.Status())
	}
	return result.StatusCode() == http.StatusOK, nil
}

// NotifyFailureMonitor - publishes failure
func (c *Access) NotifyFailureMonitor(dto MonitorDataDto) (bool, error) {
	//if there is no client, it is disabled
	if c == nil {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	body := PostMonitorFailureJSONRequestBody{
		Data: MonitorData{
			Trigger:         dto.Trigger,
			Success:         dto.Success,
			Message:         dto.Message,
			CorrelationId:   dto.CorrelationID,
			Api:             dto.API,
			Application:     dto.Application,
			Environment:     dto.Environment,
			Product:         dto.Product,
			Subscriber:      dto.Subscriber,
			SubscriberEmail: dto.Subscriberemail,
			Subscription:    dto.Subscription,
			Team:            dto.Team,
		},
		Datacontenttype: "application/json",
		Id:              uuid.New().String(),
		Source:          "axway-solace-agent",
		Specversion:     "1.0",
		Time:            time.Now().Format(time.RFC3339),
		Type:            "com.solace.iot-team.asyncapi.notification.monitor.v1",
	}
	result, err := c.Client.PostMonitorFailureWithResponse(ctx, body)
	if err != nil {
		return false, err
	}
	if result.StatusCode() >= 300 {
		return false, errors.New("Posting monitor failure notification to Endpoint returned HTTP:" + result.Status())
	}
	return result.StatusCode() == http.StatusOK, nil
}

// NotifySuccessMonitor - publishes success
func (c *Access) NotifySuccessMonitor(dto MonitorDataDto) (bool, error) {
	//if there is no client, it is disabled
	if c == nil {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout())
	defer cancel()
	body := PostMonitorSuccessJSONRequestBody{
		Data: MonitorData{
			Trigger:         dto.Trigger,
			Success:         dto.Success,
			Message:         dto.Message,
			CorrelationId:   dto.CorrelationID,
			Api:             dto.API,
			Application:     dto.Application,
			Environment:     dto.Environment,
			Product:         dto.Product,
			Subscriber:      dto.Subscriber,
			SubscriberEmail: dto.Subscriberemail,
			Subscription:    dto.Subscription,
			Team:            dto.Team,
		},
		Datacontenttype: "application/json",
		Id:              uuid.New().String(),
		Source:          "axway-solace-agent",
		Specversion:     "1.0",
		Time:            time.Now().Format(time.RFC3339),
		Type:            "com.solace.iot-team.asyncapi.notification.monitor.v1",
	}
	result, err := c.Client.PostMonitorSuccessWithResponse(ctx, body)
	if err != nil {
		return false, err
	}
	if result.StatusCode() >= 300 {
		return false, errors.New("Posting monitor failure notification to Endpoint returned HTTP:" + result.Status())
	}
	return result.StatusCode() == http.StatusOK, nil
}
