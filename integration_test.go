package main

import (
	"fmt"
	log "github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/solace-iot-team/solace-axway-agent/pkg/integrationtest"
	"os"
	"testing"
)

func Test_init(t *testing.T) {
	log.Infof("Test Test Test")
	if err := integrationtest.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
