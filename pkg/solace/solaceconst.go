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
