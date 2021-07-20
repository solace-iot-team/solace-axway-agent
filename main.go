package main

import (
	"fmt"
	"github.com/solace-iot-team/solace-axway-agent/pkg/cmd"
	"os"
	"sync"
)

var wg sync.WaitGroup

func main() {
	wg.Add(1)
	executeCommand()
	wg.Wait()
}

func executeCommand()  {
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
