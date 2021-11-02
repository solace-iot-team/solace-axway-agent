package cmd

import (
	"fmt"
	"github.com/Axway/agent-sdk/pkg/agent"
	"github.com/Axway/agent-sdk/pkg/apic"
	"github.com/Axway/agent-sdk/pkg/jobs"
	"github.com/Axway/agent-sdk/pkg/util/log"
)

// Publishes the Subscription Schema
type SubscriptionSchemaPublisherJob struct {
	jobs.Job
}

func (j *SubscriptionSchemaPublisherJob) Status() error {
	// continually called determining the status of any dependencies for the job
	// returning an error means the job should not be executed
	return nil
}

func (j *SubscriptionSchemaPublisherJob) Ready() bool {
	// called prior to executing the job the first time
	// return true when the job can begin execution, false otherwise
	return true
}

func (j *SubscriptionSchemaPublisherJob) Execute() error {
	// called each time the job should be executed
	// returning an error stops continuous jobs from executing
	log.Debugf("Registering SubscriptionSchema sol-schema-webhook-1")
	return apic.NewSubscriptionSchemaBuilder(agent.GetCentralClient()).
		SetName("sol-schema-webhook-1").
		AddProperty(apic.NewSubscriptionSchemaPropertyBuilder().
			SetName("Callback").
			IsString().
			SetDescription("Callback URL of this AsyncAPI").
			SetRequired()).
		AddProperty(apic.NewSubscriptionSchemaPropertyBuilder().
			SetName("Method").
			IsString().
			SetEnumValues([]string{"POST", "PUT"}).
			SetDescription("HTTP-Method / Verb").
			SetRequired()).
		AddProperty(apic.NewSubscriptionSchemaPropertyBuilder().
			SetName("Invocation Order").
			IsString().
			SetEnumValues([]string{"parallel", "serial"}).
			SetDescription("Parallel or serial invocation of callback url").
			SetRequired()).
		AddProperty(apic.NewSubscriptionSchemaPropertyBuilder().
			SetName("Authentication").
			IsString().
			SetEnumValues([]string{"No Authentication", "Basic Authentication", "HTTP-Header"}).
			SetDescription("Authentication method").
			SetRequired()).
		AddProperty(apic.NewSubscriptionSchemaPropertyBuilder().
			SetName("AuthenticationIdentifier").
			IsString().
			SetDescription("Authentication Username or Headername")).
		AddProperty(apic.NewSubscriptionSchemaPropertyBuilder().
			SetName("AuthenticationSecret").
			IsString().
			SetDescription("Authentication Password or Headervalue")).
		Update(true).
		Register()
}

type SubscriptionSchemaProcessorJob struct {
	jobs.Job
}

func (j *SubscriptionSchemaProcessorJob) Status() error {
	// continually called determining the status of any dependencies for the job
	// returning an error means the job should not be executed
	return nil
}

func (j *SubscriptionSchemaProcessorJob) Ready() bool {
	// called prior to executing the job the first time
	// return true when the job can begin execution, false otherwise
	return true
}

func (j *SubscriptionSchemaProcessorJob) Execute() error {
	// called each time the job should be executed
	// returning an error stops continuous jobs from executing
	log.Tracef("SubscriptionSchemaProcessorJob triggered")
	resultlist, err := agent.GetCentralClient().GetApiServicesByQuery("attributes.solace-webhook-enabled==true")
	if err != nil {
		log.Errorf("SubscriptionSchemaProcessorJob: Could not query ApiServices (attributes.solace-webhook-enabled==true)", err)
		return err
	} else {
		for _, service := range resultlist {
			log.Tracef("SubscriptionSchemaProcessorJob: Processing ApiService: %s ", service.Name)
			cq := fmt.Sprintf("metadata.references.kind==APIService and metadata.references.name==%s", service.Name)
			consumerInstances, errCi := agent.GetCentralClient().GetConsumerInstancesByQuery(cq)
			if errCi != nil {
				log.Errorf("SubscriptionSchemaProcessorJob:  Could not query ConsumerInstance", errCi)
				return errCi
			} else {
				for _, ci := range consumerInstances {
					log.Tracef("SubscriptionSchemaProcessorJob: Processing ConsumerInstance: %s ", ci.Name)
					if ci.Spec.Subscription.SubscriptionDefinition == "sol-schema-webhook-1" {
						//nothing to do
					} else {
						errAttachSchema := agent.GetCentralClient().UpdateConsumerInstanceSubscriptionDefinitionByConsumerInstanceId(ci.Metadata.ID, "sol-schema-webhook-1")
						if errAttachSchema != nil {
							log.Errorf("SubscriptionSchemaProcessorJob: Could not attach Subscription Schema to ConsumerInstance:%s", ci.Name, errAttachSchema)
							return errAttachSchema
						} else {
							log.Infof("SubscriptionSchemaProcessorJob: Attached SubscriptionSchema: %s to ConsumerInstance: %s", "sol-schema-webhook-1", ci.Name)
						}
					}
				}
			}
		}
	}
	return nil
}
