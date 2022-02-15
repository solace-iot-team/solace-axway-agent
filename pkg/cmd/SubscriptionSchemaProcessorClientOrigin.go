package cmd

import (
	"fmt"
	"github.com/Axway/agent-sdk/pkg/agent"
	"github.com/Axway/agent-sdk/pkg/apic"
	"github.com/Axway/agent-sdk/pkg/jobs"
	"github.com/Axway/agent-sdk/pkg/util/log"
	"github.com/solace-iot-team/solace-axway-agent/pkg/solace"
)

// SubscriptionSchemaPublisherJob the publishing job
type SubscriptionSchemaPublisherClientOriginJob struct {
	jobs.Job
}

// Status - of this job
func (j *SubscriptionSchemaPublisherClientOriginJob) Status() error {
	// continually called determining the status of any dependencies for the job
	// returning an error means the job should not be executed
	return nil
}

// Ready - is this job ready
func (j *SubscriptionSchemaPublisherClientOriginJob) Ready() bool {
	// called prior to executing the job the first time
	// return true when the job can begin execution, false otherwise
	return true
}

// Execute - executes this job
func (j *SubscriptionSchemaPublisherClientOriginJob) Execute() error {
	// called each time the job should be executed
	// returning an error stops continuous jobs from executing
	log.Debugf("Registering SubscriptionSchema sol-schema-clientorigin-1")
	return apic.NewSubscriptionSchemaBuilder(agent.GetCentralClient()).
		SetName(solace.SolaceClientOriginSubscriptionSchema).
		AddProperty(apic.NewSubscriptionSchemaPropertyBuilder().
			SetName(solace.SolaceClientOrigin).
			IsString().
			SetDescription("Client Origin (IP, ...) ")).
		Update(true).
		Register()
}

// SubscriptionSchemaProcessorJob - the job
type SubscriptionSchemaProcessorClientOriginJob struct {
	jobs.Job
}

// Status - the status of this job
func (j *SubscriptionSchemaProcessorClientOriginJob) Status() error {
	// continually called determining the status of any dependencies for the job
	// returning an error means the job should not be executed
	return nil
}

// Ready - is this job ready
func (j *SubscriptionSchemaProcessorClientOriginJob) Ready() bool {
	// called prior to executing the job the first time
	// return true when the job can begin execution, false otherwise
	return true
}

// Execute - executes this job
func (j *SubscriptionSchemaProcessorClientOriginJob) Execute() error {
	// called each time the job should be executed
	// returning an error stops continuous jobs from executing
	log.Tracef("SubscriptionSchemaProcessorClientOriginJob triggered")
	resultlist, err := agent.GetCentralClient().GetAPIServicesByQuery(solace.SolaceClientOriginEnabledAttributeQuery)
	if err != nil {
		log.Errorf("SubscriptionSchemaProcessorClientOriginJob: Could not query ApiServices (%s)", solace.SolaceClientOriginEnabledAttributeQuery, err)
		return err
	}
	for _, service := range resultlist {
		log.Tracef("SubscriptionSchemaProcessorClientOriginJob: Processing ApiService: %s ", service.Name)
		cq := fmt.Sprintf("metadata.references.kind==APIService and metadata.references.name==%s", service.Name)
		consumerInstances, errCi := agent.GetCentralClient().GetConsumerInstancesByQuery(cq)
		if errCi != nil {
			log.Errorf("SubscriptionSchemaProcessorClientOriginJob:  Could not query ConsumerInstances", errCi)
			return errCi
		}
		for _, ci := range consumerInstances {
			log.Tracef("SubscriptionSchemaProcessorClientOriginJob: Processing ConsumerInstance: %s ", ci.Name)
			if ci.Spec.Subscription.SubscriptionDefinition == solace.SolaceClientOriginSubscriptionSchema {
				//nothing to do
			} else {
				errAttachSchema := agent.GetCentralClient().UpdateConsumerInstanceSubscriptionDefinitionByConsumerInstanceID(ci.Metadata.ID, solace.SolaceClientOriginSubscriptionSchema)
				if errAttachSchema != nil {
					log.Errorf("SubscriptionSchemaProcessorClientOriginJob: Could not attach Subscription Schema to ConsumerInstance:%s", ci.Name, errAttachSchema)
					return errAttachSchema
				}
				log.Infof("SubscriptionSchemaProcessorClientOriginJob: Attached SubscriptionSchema: %s to ConsumerInstance: %s", solace.SolaceClientOriginSubscriptionSchema, ci.Name)
			}
		}

	}
	return nil
}
