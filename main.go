package main

import (
	"fmt"
	"github.com/solace-iot-team/solace-axway-agent/pkg/cmd"
	"os"
)

func main() {
	root := cmd.RootCmd
	if err := root.RootCmd().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
