package main

import (
	log "github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/solace-iot-team/solace-axway-agent/pkg/integrationtest"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if err := integrationtest.RootCmd.Execute(); err != nil {
		log.Error("Bootstrapping RootCmd failed", err)
		os.Exit(1)
	}
	exitVal := m.Run()
	os.Exit(exitVal)
}

func TestConnector(t *testing.T) {
	if err := integrationtest.ExecuteIntegrationTestsConnector(t); err != nil {
		t.Error("Integration Test of the Connector failed", err)
		t.Failed()
	} else {
		t.Logf("Integration Test of Connector is ok")
	}
}

func TestMiddleware(t *testing.T) {
	if err := integrationtest.ExecuteIntegrationTestMiddleware(); err != nil {
		t.Error("Integration Test of Middleware failed", err)
		t.Failed()
	} else {
		t.Logf("Integration Test of Middleware is ok")
	}
}
