package solace

//Solace Callback Constants
const (
	SolaceCallbackSubscriptionSchema                   = "sol-schema-webhook-1"
	SolaceClientOriginSubscriptionSchema               = "sol-schema-clientorigin-1"
	SolaceCallbackEnabledAttributeQuery                = "attributes.solace-webhook-enabled==true"
	SolaceClientOriginEnabledAttributeQuery            = "attributes.solace-clientorigin-enabled==true"
	SolaceCallback                                     = "Callback"
	SolaceCallbackTrustedCNS                           = "TrustedCnames"
	SolaceHTTPMethod                                   = "Method"
	SolaceHTTPMethodPost                               = "Post"
	SolaceHTTPMethodPut                                = "Put"
	SolaceInvocationOrder                              = "InvocationOrder"
	SolaceInvocationOrderParallel                      = "parallel"
	SolaceInvocationOrderSerial                        = "serial"
	SolaceAuthenticationMethod                         = "Authentication"
	SolaceAuthenticationMethodNoAuthentication         = "NoAuthentication"
	SolaceAuthenticationMethodBasicAuthentication      = "BasicAuthentication"
	SolaceAuthenticationMethodHTTPHeaderAuthentication = "HttpHeader"
	SolaceAuthenticationIdentifier                     = "AuthenticationIdentifier"
	SolaceAuthenticationSecret                         = "AuthenticationSecret"

	SolaceClientOrigin = "ClientOrigin"
)

var AxwaySolaceProtocolMapping = map[string]string{
	"amqp":              "amqp",
	"amqps":             "amqps",
	"jms":               "jms",
	"jms-secure":        "secure-jms",
	"mqtt":              "mqtt",
	"secure-mqtt":       "secure-mqtt",
	"solace":            "smf",
	"solace-secure":     "smfs",
	"solace-compressed": "compressed-smf",
	"ws":                "ws-mqtt",
	"wss":               "wss-mqtt",
	"http":              "http",
	"https":             "https",
}
