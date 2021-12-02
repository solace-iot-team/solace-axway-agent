// Package Notification provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.8.2 DO NOT EDIT.
package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Defines values for MonitorDataTrigger.
const (
	MonitorDataTriggerSubscribe MonitorDataTrigger = "subscribe"

	MonitorDataTriggerUnsubscribe MonitorDataTrigger = "unsubscribe"
)

// Defines values for MonitoringEventDatacontenttype.
const (
	MonitoringEventDatacontenttypeApplicationjson MonitoringEventDatacontenttype = "application/json"
)

// Defines values for MonitoringEventType.
const (
	MonitoringEventTypeComSolaceIotTeamAsyncapiNotificationMonitorV1 MonitoringEventType = "com.solace.iot-team.asyncapi.notification.monitor.v1"
)

// Defines values for NotificationSubscribeEventDatacontenttype.
const (
	NotificationSubscribeEventDatacontenttypeApplicationjson NotificationSubscribeEventDatacontenttype = "application/json"
)

// Defines values for NotificationSubscribeEventType.
const (
	NotificationSubscribeEventTypeComSolaceIotTeamAsyncapiNotificationSubscribeV1 NotificationSubscribeEventType = "com.solace.iot-team.asyncapi.notification.subscribe.v1"
)

// Defines values for NotificationUnsubscribeEventDatacontenttype.
const (
	NotificationUnsubscribeEventDatacontenttypeApplicationjson NotificationUnsubscribeEventDatacontenttype = "application/json"
)

// Defines values for NotificationUnsubscribeEventType.
const (
	NotificationUnsubscribeEventTypeComSolaceIotTeamAsyncapiNotificationUnsubscribeV1 NotificationUnsubscribeEventType = "com.solace.iot-team.asyncapi.notification.unsubscribe.v1"
)

// HealthEvent defines model for HealthEvent.
type HealthEvent struct {
	Echo string `json:"echo"`
}

// MonitorData defines model for MonitorData.
type MonitorData struct {
	Api             string             `json:"api"`
	Application     string             `json:"application"`
	CorrelationId   string             `json:"correlationId"`
	Environment     string             `json:"environment"`
	Message         *string            `json:"message,omitempty"`
	Product         string             `json:"product"`
	Subscriber      string             `json:"subscriber"`
	SubscriberEmail string             `json:"subscriberEmail"`
	Subscription    string             `json:"subscription"`
	Success         bool               `json:"success"`
	Team            string             `json:"team"`
	Trigger         MonitorDataTrigger `json:"trigger"`
}

// MonitorDataTrigger defines model for MonitorData.Trigger.
type MonitorDataTrigger string

// MonitoringEvent defines model for MonitoringEvent.
type MonitoringEvent struct {
	Data            MonitorData                    `json:"data"`
	Datacontenttype MonitoringEventDatacontenttype `json:"datacontenttype"`
	Id              string                         `json:"id"`
	Source          string                         `json:"source"`
	Specversion     string                         `json:"specversion"`
	Time            string                         `json:"time"`
	Type            MonitoringEventType            `json:"type"`
}

// MonitoringEventDatacontenttype defines model for MonitoringEvent.Datacontenttype.
type MonitoringEventDatacontenttype string

// MonitoringEventType defines model for MonitoringEvent.Type.
type MonitoringEventType string

// NotificationSubscribeEvent defines model for NotificationSubscribeEvent.
type NotificationSubscribeEvent struct {
	Data            SubscribeData                             `json:"data"`
	Datacontenttype NotificationSubscribeEventDatacontenttype `json:"datacontenttype"`
	Id              string                                    `json:"id"`
	Source          string                                    `json:"source"`
	Specversion     string                                    `json:"specversion"`
	Time            string                                    `json:"time"`
	Type            NotificationSubscribeEventType            `json:"type"`
}

// NotificationSubscribeEventDatacontenttype defines model for NotificationSubscribeEvent.Datacontenttype.
type NotificationSubscribeEventDatacontenttype string

// NotificationSubscribeEventType defines model for NotificationSubscribeEvent.Type.
type NotificationSubscribeEventType string

// NotificationUnsubscribeEvent defines model for NotificationUnsubscribeEvent.
type NotificationUnsubscribeEvent struct {
	Data            UnsubscribeData                             `json:"data"`
	Datacontenttype NotificationUnsubscribeEventDatacontenttype `json:"datacontenttype"`
	Id              string                                      `json:"id"`
	Source          string                                      `json:"source"`
	Specversion     string                                      `json:"specversion"`
	Time            string                                      `json:"time"`
	Type            NotificationUnsubscribeEventType            `json:"type"`
}

// NotificationUnsubscribeEventDatacontenttype defines model for NotificationUnsubscribeEvent.Datacontenttype.
type NotificationUnsubscribeEventDatacontenttype string

// NotificationUnsubscribeEventType defines model for NotificationUnsubscribeEvent.Type.
type NotificationUnsubscribeEventType string

// SubscribeData defines model for SubscribeData.
type SubscribeData struct {
	Api             string                    `json:"api"`
	Application     string                    `json:"application"`
	ApplicationData map[string]interface{}    `json:"applicationData"`
	AsyncApis       []*map[string]interface{} `json:"asyncApis"`
	Environment     string                    `json:"environment"`
	Product         string                    `json:"product"`
	Subscriber      string                    `json:"subscriber"`
	SubscriberEmail string                    `json:"subscriberEmail"`
	Subscription    string                    `json:"subscription"`
	Team            string                    `json:"team"`
}

// UnsubscribeData defines model for UnsubscribeData.
type UnsubscribeData struct {
	Api             string `json:"api"`
	Application     string `json:"application"`
	Environment     string `json:"environment"`
	Product         string `json:"product"`
	Subscriber      string `json:"subscriber"`
	SubscriberEmail string `json:"subscriberEmail"`
	Subscription    string `json:"subscription"`
	Team            string `json:"team"`
}

// PostHealthJSONBody defines parameters for PostHealth.
type PostHealthJSONBody HealthEvent

// PostMonitorFailureJSONBody defines parameters for PostMonitorFailure.
type PostMonitorFailureJSONBody MonitoringEvent

// PostMonitorSuccessJSONBody defines parameters for PostMonitorSuccess.
type PostMonitorSuccessJSONBody MonitoringEvent

// PostSubscribeJSONBody defines parameters for PostSubscribe.
type PostSubscribeJSONBody NotificationSubscribeEvent

// PostUnsubscribeJSONBody defines parameters for PostUnsubscribe.
type PostUnsubscribeJSONBody NotificationUnsubscribeEvent

// PostHealthJSONRequestBody defines body for PostHealth for application/json ContentType.
type PostHealthJSONRequestBody PostHealthJSONBody

// PostMonitorFailureJSONRequestBody defines body for PostMonitorFailure for application/json ContentType.
type PostMonitorFailureJSONRequestBody PostMonitorFailureJSONBody

// PostMonitorSuccessJSONRequestBody defines body for PostMonitorSuccess for application/json ContentType.
type PostMonitorSuccessJSONRequestBody PostMonitorSuccessJSONBody

// PostSubscribeJSONRequestBody defines body for PostSubscribe for application/json ContentType.
type PostSubscribeJSONRequestBody PostSubscribeJSONBody

// PostUnsubscribeJSONRequestBody defines body for PostUnsubscribe for application/json ContentType.
type PostUnsubscribeJSONRequestBody PostUnsubscribeJSONBody

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// PostHealth request with any body
	PostHealthWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	PostHealth(ctx context.Context, body PostHealthJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// PostMonitorFailure request with any body
	PostMonitorFailureWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	PostMonitorFailure(ctx context.Context, body PostMonitorFailureJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// PostMonitorSuccess request with any body
	PostMonitorSuccessWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	PostMonitorSuccess(ctx context.Context, body PostMonitorSuccessJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// PostSubscribe request with any body
	PostSubscribeWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	PostSubscribe(ctx context.Context, body PostSubscribeJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// PostUnsubscribe request with any body
	PostUnsubscribeWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	PostUnsubscribe(ctx context.Context, body PostUnsubscribeJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) PostHealthWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostHealthRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostHealth(ctx context.Context, body PostHealthJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostHealthRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostMonitorFailureWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostMonitorFailureRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostMonitorFailure(ctx context.Context, body PostMonitorFailureJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostMonitorFailureRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostMonitorSuccessWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostMonitorSuccessRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostMonitorSuccess(ctx context.Context, body PostMonitorSuccessJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostMonitorSuccessRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostSubscribeWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostSubscribeRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostSubscribe(ctx context.Context, body PostSubscribeJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostSubscribeRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostUnsubscribeWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostUnsubscribeRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostUnsubscribe(ctx context.Context, body PostUnsubscribeJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostUnsubscribeRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewPostHealthRequest calls the generic PostHealth builder with application/json body
func NewPostHealthRequest(server string, body PostHealthJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewPostHealthRequestWithBody(server, "application/json", bodyReader)
}

// NewPostHealthRequestWithBody generates requests for PostHealth with any type of body
func NewPostHealthRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/health")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewPostMonitorFailureRequest calls the generic PostMonitorFailure builder with application/json body
func NewPostMonitorFailureRequest(server string, body PostMonitorFailureJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewPostMonitorFailureRequestWithBody(server, "application/json", bodyReader)
}

// NewPostMonitorFailureRequestWithBody generates requests for PostMonitorFailure with any type of body
func NewPostMonitorFailureRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/monitor/failure")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewPostMonitorSuccessRequest calls the generic PostMonitorSuccess builder with application/json body
func NewPostMonitorSuccessRequest(server string, body PostMonitorSuccessJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewPostMonitorSuccessRequestWithBody(server, "application/json", bodyReader)
}

// NewPostMonitorSuccessRequestWithBody generates requests for PostMonitorSuccess with any type of body
func NewPostMonitorSuccessRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/monitor/success")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewPostSubscribeRequest calls the generic PostSubscribe builder with application/json body
func NewPostSubscribeRequest(server string, body PostSubscribeJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewPostSubscribeRequestWithBody(server, "application/json", bodyReader)
}

// NewPostSubscribeRequestWithBody generates requests for PostSubscribe with any type of body
func NewPostSubscribeRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/subscribe")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewPostUnsubscribeRequest calls the generic PostUnsubscribe builder with application/json body
func NewPostUnsubscribeRequest(server string, body PostUnsubscribeJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewPostUnsubscribeRequestWithBody(server, "application/json", bodyReader)
}

// NewPostUnsubscribeRequestWithBody generates requests for PostUnsubscribe with any type of body
func NewPostUnsubscribeRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/unsubscribe")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// PostHealth request with any body
	PostHealthWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostHealthResponse, error)

	PostHealthWithResponse(ctx context.Context, body PostHealthJSONRequestBody, reqEditors ...RequestEditorFn) (*PostHealthResponse, error)

	// PostMonitorFailure request with any body
	PostMonitorFailureWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostMonitorFailureResponse, error)

	PostMonitorFailureWithResponse(ctx context.Context, body PostMonitorFailureJSONRequestBody, reqEditors ...RequestEditorFn) (*PostMonitorFailureResponse, error)

	// PostMonitorSuccess request with any body
	PostMonitorSuccessWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostMonitorSuccessResponse, error)

	PostMonitorSuccessWithResponse(ctx context.Context, body PostMonitorSuccessJSONRequestBody, reqEditors ...RequestEditorFn) (*PostMonitorSuccessResponse, error)

	// PostSubscribe request with any body
	PostSubscribeWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostSubscribeResponse, error)

	PostSubscribeWithResponse(ctx context.Context, body PostSubscribeJSONRequestBody, reqEditors ...RequestEditorFn) (*PostSubscribeResponse, error)

	// PostUnsubscribe request with any body
	PostUnsubscribeWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostUnsubscribeResponse, error)

	PostUnsubscribeWithResponse(ctx context.Context, body PostUnsubscribeJSONRequestBody, reqEditors ...RequestEditorFn) (*PostUnsubscribeResponse, error)
}

type PostHealthResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r PostHealthResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PostHealthResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type PostMonitorFailureResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r PostMonitorFailureResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PostMonitorFailureResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type PostMonitorSuccessResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r PostMonitorSuccessResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PostMonitorSuccessResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type PostSubscribeResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r PostSubscribeResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PostSubscribeResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type PostUnsubscribeResponse struct {
	Body         []byte
	HTTPResponse *http.Response
}

// Status returns HTTPResponse.Status
func (r PostUnsubscribeResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PostUnsubscribeResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// PostHealthWithBodyWithResponse request with arbitrary body returning *PostHealthResponse
func (c *ClientWithResponses) PostHealthWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostHealthResponse, error) {
	rsp, err := c.PostHealthWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostHealthResponse(rsp)
}

func (c *ClientWithResponses) PostHealthWithResponse(ctx context.Context, body PostHealthJSONRequestBody, reqEditors ...RequestEditorFn) (*PostHealthResponse, error) {
	rsp, err := c.PostHealth(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostHealthResponse(rsp)
}

// PostMonitorFailureWithBodyWithResponse request with arbitrary body returning *PostMonitorFailureResponse
func (c *ClientWithResponses) PostMonitorFailureWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostMonitorFailureResponse, error) {
	rsp, err := c.PostMonitorFailureWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostMonitorFailureResponse(rsp)
}

func (c *ClientWithResponses) PostMonitorFailureWithResponse(ctx context.Context, body PostMonitorFailureJSONRequestBody, reqEditors ...RequestEditorFn) (*PostMonitorFailureResponse, error) {
	rsp, err := c.PostMonitorFailure(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostMonitorFailureResponse(rsp)
}

// PostMonitorSuccessWithBodyWithResponse request with arbitrary body returning *PostMonitorSuccessResponse
func (c *ClientWithResponses) PostMonitorSuccessWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostMonitorSuccessResponse, error) {
	rsp, err := c.PostMonitorSuccessWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostMonitorSuccessResponse(rsp)
}

func (c *ClientWithResponses) PostMonitorSuccessWithResponse(ctx context.Context, body PostMonitorSuccessJSONRequestBody, reqEditors ...RequestEditorFn) (*PostMonitorSuccessResponse, error) {
	rsp, err := c.PostMonitorSuccess(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostMonitorSuccessResponse(rsp)
}

// PostSubscribeWithBodyWithResponse request with arbitrary body returning *PostSubscribeResponse
func (c *ClientWithResponses) PostSubscribeWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostSubscribeResponse, error) {
	rsp, err := c.PostSubscribeWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostSubscribeResponse(rsp)
}

func (c *ClientWithResponses) PostSubscribeWithResponse(ctx context.Context, body PostSubscribeJSONRequestBody, reqEditors ...RequestEditorFn) (*PostSubscribeResponse, error) {
	rsp, err := c.PostSubscribe(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostSubscribeResponse(rsp)
}

// PostUnsubscribeWithBodyWithResponse request with arbitrary body returning *PostUnsubscribeResponse
func (c *ClientWithResponses) PostUnsubscribeWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostUnsubscribeResponse, error) {
	rsp, err := c.PostUnsubscribeWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostUnsubscribeResponse(rsp)
}

func (c *ClientWithResponses) PostUnsubscribeWithResponse(ctx context.Context, body PostUnsubscribeJSONRequestBody, reqEditors ...RequestEditorFn) (*PostUnsubscribeResponse, error) {
	rsp, err := c.PostUnsubscribe(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostUnsubscribeResponse(rsp)
}

// ParsePostHealthResponse parses an HTTP response from a PostHealthWithResponse call
func ParsePostHealthResponse(rsp *http.Response) (*PostHealthResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &PostHealthResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParsePostMonitorFailureResponse parses an HTTP response from a PostMonitorFailureWithResponse call
func ParsePostMonitorFailureResponse(rsp *http.Response) (*PostMonitorFailureResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &PostMonitorFailureResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParsePostMonitorSuccessResponse parses an HTTP response from a PostMonitorSuccessWithResponse call
func ParsePostMonitorSuccessResponse(rsp *http.Response) (*PostMonitorSuccessResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &PostMonitorSuccessResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParsePostSubscribeResponse parses an HTTP response from a PostSubscribeWithResponse call
func ParsePostSubscribeResponse(rsp *http.Response) (*PostSubscribeResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &PostSubscribeResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}

// ParsePostUnsubscribeResponse parses an HTTP response from a PostUnsubscribeWithResponse call
func ParsePostUnsubscribeResponse(rsp *http.Response) (*PostUnsubscribeResponse, error) {
	bodyBytes, err := ioutil.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return nil, err
	}

	response := &PostUnsubscribeResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	return response, nil
}
