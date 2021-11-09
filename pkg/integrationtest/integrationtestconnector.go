package integrationtest

import (
	"fmt"
	"github.com/Axway/agent-sdk/pkg/agent"
	"github.com/Axway/agent-sdk/pkg/cmd/agentsync"
	"github.com/Axway/agent-sdk/pkg/cmd/properties"
	"github.com/Axway/agent-sdk/pkg/cmd/properties/resolver"
	"github.com/Axway/agent-sdk/pkg/config"
	"github.com/Axway/agent-sdk/pkg/util"
	hc "github.com/Axway/agent-sdk/pkg/util/healthcheck"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"math/rand"
	"strings"
	"time"
)

// Constants for cmd flags
const (
	PathConfigFlag        = "pathConfig"
	BeatsPathConfigFlag   = "path.config"
	EnvFileFlag           = "envFile"
	EnvFileFlagDesciption = "Path of the file with environment variables to override configuration"
)

// CommandHandler - Root command execution handler
type CommandHandler func() error

// InitConfigHandler - Handler to be invoked on config initialization
type InitConfigHandler func(centralConfig config.CentralConfig) (interface{}, error)

type ConnectorIntegrationTestCmd interface {
	RootCmd() *cobra.Command
	Execute() error

	// Get the agentType
	GetAgentType() config.AgentType
	AddCommand(*cobra.Command)

	GetProperties() properties.Properties
}

type connectorIntegrationTestCmd struct {
	agentName         string
	rootCmd           *cobra.Command
	commandHandler    CommandHandler
	initConfigHandler InitConfigHandler
	agentType         config.AgentType
	props             properties.Properties
	statusCfg         config.StatusConfig
	centralCfg        config.CentralConfig
	agentCfg          interface{}
	secretResolver    resolver.SecretResolver
}

func init() {
	// initalize the global Source used by rand.Intn() and other functions of the rand package using rand.Seed().
	rand.Seed(time.Now().UnixNano())
}

// NewRootCmd - Creates a new Agent Root Command
func NewRootCmd(exeName, desc string, initConfigHandler InitConfigHandler, commandHandler CommandHandler, agentType config.AgentType) ConnectorIntegrationTestCmd {
	c := &connectorIntegrationTestCmd{
		agentName:         exeName,
		commandHandler:    commandHandler,
		initConfigHandler: initConfigHandler,
		agentType:         agentType,
		secretResolver:    resolver.NewSecretResolver(),
	}

	c.rootCmd = &cobra.Command{
		Use:     c.agentName,
		Short:   desc,
		Version: "1.0",
		RunE:    c.run,
		PreRunE: c.initialize,
	}

	c.props = properties.NewPropertiesWithSecretResolver(c.rootCmd, c.secretResolver)
	c.addBaseProps()
	config.AddLogConfigProperties(c.props, fmt.Sprintf("%s.log", exeName))
	agentsync.AddSyncConfigProperties(c.props)
	config.AddCentralConfigProperties(c.props, agentType)
	config.AddStatusConfigProperties(c.props)

	hc.SetNameAndVersion(exeName, c.rootCmd.Version)

	// Call the config add props
	return c
}

// Add the command line properties for the logger and path config
func (c *connectorIntegrationTestCmd) addBaseProps() {
	c.props.AddStringPersistentFlag(PathConfigFlag, ".", "Path to the directory containing the YAML configuration file for the agent")
	c.props.AddStringPersistentFlag(EnvFileFlag, "", EnvFileFlagDesciption)
}

func (c *connectorIntegrationTestCmd) initialize(cmd *cobra.Command, args []string) error {
	_, envFile := c.props.StringFlagValue(EnvFileFlag)
	err := util.LoadEnvFromFile(envFile)
	if err != nil {
		return err
	}
	_, configFilePath := c.props.StringFlagValue(PathConfigFlag)
	viper.SetConfigName(c.agentName)
	// viper.SetConfigType("yaml")  //Comment out since yaml, yml is a support extension already.  We need an updated story to take into account the other supported extensions
	viper.AddConfigPath(configFilePath)
	viper.AddConfigPath(".")
	viper.SetTypeByDefaultValue(true)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	err = viper.ReadInConfig()
	if err != nil {
		if envFile == "" {
			return err
		} else if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}
	return nil
}

// initConfig - Initializes the central config and invokes initConfig handler
// to initialize the agent config. Performs validation on returned agent config
func (c *connectorIntegrationTestCmd) initConfig() error {
	// Clean the secret map on config change
	c.secretResolver.ResetResolver()

	_, err := config.ParseAndSetupLogConfig(c.GetProperties())
	if err != nil {
		return err
	}

	c.statusCfg, err = config.ParseStatusConfig(c.GetProperties())
	err = c.statusCfg.ValidateCfg()
	if err != nil {
		return err
	}

	// Init Central Config
	c.centralCfg, err = config.ParseCentralConfig(c.GetProperties(), c.GetAgentType())
	if err != nil {
		return err
	}

	// must set the hc config now, because the healthchecker loop starts in agent.Initialize
	hc.SetStatusConfig(c.statusCfg)

	err = agent.Initialize(c.centralCfg)
	if err != nil {
		return err
	}
	// Initialize Agent Config
	c.agentCfg, err = c.initConfigHandler(c.centralCfg)
	if err != nil {
		return err
	}

	if c.agentCfg != nil {
		err := agent.ApplyResourceToConfig(c.agentCfg)
		if err != nil {
			return err
		}

		// Validate Agent Config
		err = config.ValidateConfig(c.agentCfg)
		if err != nil {
			return err
		}
	}

	return nil
}

// run - Executes the agent command
func (c *connectorIntegrationTestCmd) run(cmd *cobra.Command, args []string) (err error) {
	err = c.initConfig()
	statusText := ""
	if err == nil {
		log.Infof("Starting Integration Tests for Connector")
		if c.commandHandler != nil {

			err = c.commandHandler()
			if err != nil {
				log.Error(err.Error())
				statusText = err.Error()
			}
		}
	} else {
		statusText = err.Error()
	}
	status := agent.AgentStopped
	if statusText != "" {
		status = agent.AgentFailed
	}
	agent.UpdateStatus(status, statusText)
	return
}

func (c *connectorIntegrationTestCmd) RootCmd() *cobra.Command {
	return c.rootCmd
}

func (c *connectorIntegrationTestCmd) Execute() error {
	return c.rootCmd.Execute()
}

func (c *connectorIntegrationTestCmd) GetAgentType() config.AgentType {
	return c.agentType
}

func (c *connectorIntegrationTestCmd) GetProperties() properties.Properties {
	return c.props
}

func (c *connectorIntegrationTestCmd) AddCommand(cmd *cobra.Command) {
	c.rootCmd.AddCommand(cmd)
}
