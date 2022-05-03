Parameter Settings of AsyncAPIs in Axway Amplify
================================================

AsyncAPIs with Webhooks
-----------------------

AsyncAPI subscriptions can be enriched with Webhooks during the subscription process in Axway Amplify. Solace PubSub+ message brokers will invoke a HTTP-Endpoint (`POST` or `PUT` HTTP verbs are supported).

To enable webhooks a specific Axway Amplify Service `Attribute` must be provided during the creation of a Axway Amplify Service:

Attribute `solace-webhook-enabled=true`

.. note::
  `Attributes` *cannot* be changed, added or removed for an `API Service` *after* the creation of this service through the Web UI.

* Open `Topology` section in Axway Amplify Web UI
* Pick an `Environment`
* Add a new `API Service`

  * Select `AsyncAPI` as specification type
  * Follow Web UI Wizzard
  * Add `Attribute` (key/value)

  ========================== ================================ ===================================
  Name                       Value                            Description
  ========================== ================================ ===================================
  solace-webhook-enabled     true                             Enables webhooks support
  ========================== ================================ ===================================


AsyncAPIs with Queues
---------------------

AsyncAPI subscriptions can trigger the provisioning of a dedicated Solace PubSub+ queue for each distinct subscription during the subscription process in Axway Amplify.

To enable the provisioning of queues per subscription specific Axway Amplify Service `Attributes` must be provided during the creation of a Axway Amplify Service:

Attribute `solace-queue-require=true`

.. note::
  `Attributes` *cannot* be changed, added or removed for an `API Service` *after* creation of this service through the Web UI.

* Open `Topology` section in Axway Amplify Web UI
* Pick an `Environment`
* Add a new `API Service`

  * Select `ASyncAPI` as specification type
  * Follow Web UI Wizzard
  * Add all of the following `Attributes`

  ========================== ================================ ===================================
  Name                       Value                            Description
  ========================== ================================ ===================================
  solace-queue-require       true                             Enables queue provisioning
  solace-queue-accesstype    ( exclusive | non-exclusive )    Access mode for the queue
  solace-queue-maxttl        min: 0, max: 9007199254740991    Retention policy for messages on the queue, in seconds
  solace-queue-maxspoolusage min: 0, max: 9007199254740991    The maximum message spool usage allowed by the Queue, in megabytes (MB)

                                                              A value of 0 only allows spooling of the last message received and disables quota checking

  ========================== ================================ ===================================


