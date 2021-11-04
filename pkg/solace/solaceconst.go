package solace

//Solace Callback Constants
const (
	SolaceCallbackSubscriptionSchema                   = "sol-schema-webhook-1"
	SolaceCallbackEnabledAttributeQuery                = "attributes.solace-webhook-enabled==true"
	SolaceCallback                                     = "Callback"
	SolaceCallbackTrustedCNS                           = "TrustedCnames"
	SolaceHttpMethod                                   = "Method"
	SolaceHttpMethodPost                               = "Post"
	SolaceHttpMethodPut                                = "Put"
	SolaceInvocationOrder                              = "InvocationOrder"
	SolaceInvocationOrderParallel                      = "parallel"
	SolaceInvocationOrderSerial                        = "serial"
	SolaceAuthenticationMethod                         = "Authentication"
	SolaceAuthenticationMethodNoAuthentication         = "NoAuthentication"
	SolaceAuthenticationMethodBasicAuthentication      = "BasicAuthentication"
	SolaceAuthenticationMethodHttpHeaderAuthentication = "HttpHeader"
	SolaceAuthenticationIdentifier                     = "AuthenticationIdentifier"
	SolaceAuthenticationSecret                         = "AuthenticationSecret"
)
