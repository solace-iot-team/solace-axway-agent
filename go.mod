// CHANGE_HERE - Change the module path below to reference packages correctly
module github.com/solace-iot-team/solace-axway-agent

go 1.16

require (
	github.com/Axway/agent-sdk v1.1.7
	github.com/deepmap/oapi-codegen v1.8.1
	github.com/google/uuid v1.3.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/sys v0.0.0-20210510120138-977fb7262007 // indirect
	gopkg.in/yaml.v2 v2.3.0
)

replace (
	// Option A:
	// to bind against local version of agent-sdk (or fork of it) point to the project root
	//github.com/Axway/agent-sdk v1.1.7 => ../agent-sdk

	// Option B:
	//github.com/Axway/agent-sdk v1.1.7 => github.com/solace-iot-team/agent-sdk SOL-8
	github.com/Axway/agent-sdk v1.1.7 => github.com/solace-iot-team/agent-sdk v1.0.20210617-0.20211215165841-56ff1b7b6fb5
	//
	// go mod tidy (will do the magic)

	github.com/Shopify/sarama => github.com/elastic/sarama v0.0.0-20191122160421-355d120d0970
	github.com/dop251/goja => github.com/andrewkroh/goja v0.0.0-20190128172624-dd2ac4456e20
	github.com/fsnotify/fsevents => github.com/fsnotify/fsevents v0.1.1
)
