# OpenAPI Code Generation

Codegenerator used to create clients: [https://github.com/deepmap/oapi-codegen](https://github.com/deepmap/oapi-codegen)

## Solace Connector 

### Step 1: Prepare `connector.yml`

* rename `/components/parameters/organization` with `.../orgparameter`
  * rename all references accordingly `#/components/parameters/organization` must get replaced with `#/components/parameters/orgparameter`
* remove `allOf` and merge properties manually
  * `EnvironmentListItem`
* `anyOf` is not getting handled by code generator. 

### Step 2: Generate Code
`oapi-codegen -generate types,client connector.yaml > connector.gen.go`

### Step 3: Adjust `connector.gen.go`

* remove redundant code 

## Notifier

### Step 1: Generate Code
`oapi-codegen -generate types,client notification.yaml > notification.gen.go`

### Step 2: Adjust `notification.gen.go`

Change `AsyncApis` and add pointer to map `[]*map[string]interface{}`
```go
type SubscribeData struct {
    Api             string                   `json:"api"`
    Application     string                   `json:"application"`
    ApplicationData map[string]interface{}   `json:"applicationData"`
    AsyncApis       []*map[string]interface{} `json:"asyncApis"`
    Environment     string                   `json:"environment"`
    Product         string                   `json:"product"`
    Subscriber      string                   `json:"subscriber"`
    SubscriberEmail string                   `json:"subscriberEmail"`
    Subscription    string                   `json:"subscription"`
    Team            string                   `json:"team"`
}
```