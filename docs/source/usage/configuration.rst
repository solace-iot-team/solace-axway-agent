Parameter Settings of AsyncAPIs in Axway Amplify
================================================

AsyncAPIs with Webhooks
-----------------------

AsyncAPI subscriptions can get enriched with Webhooks during the subscription process in Axway Amplify. Solace PubSub+ message brokers will invoke a HTTP-Endpoint (`POST` or `PUT` HTTP verbs are supported).

To enable webhooks a specific Axway Amplify Service `Attribute` must get provided during the creation of a Axway Amplify Service:

Attribute `solace-webhook-enabled=true`

.. note::
  `Attributes` can *not* get changed, added or removed for an `API Service` *after* the creation of this service through the Web UI.

* Open `Topology` section in Axway Amplify Web UI
* Pick an `Environment`
* Add a new `API Service`

  * Select `OpenAPI 3` as `Specification Type`
  * Follow Web UI Wizzard
  * Add `Attribute` (key/value)

  ========================== ================================ ===================================
  Name                       Value                            Description
  ========================== ================================ ===================================
  solace-webhook-enabled     true                             Enables invocation of Webhooks
  ========================== ================================ ===================================


AsyncAPIs with Queues
---------------------

AsyncAPI subscriptions can trigger the provisioning of a dedicated Solace PubSub+ queue for each distinct subscription during the subscription process in Axway Amplify.

To enable the provisioning of queues per subscription specific Axway Amplify Service `Attributes` must get provided during the creation of a Axway Amplify Service:

Attribute `solace-queue-require=true`

.. note::
  `Attributes` can *not* get changed, added or removed for an `API Service` *after* creation of this service through the Web UI.

* Open `Topology` section in Axway Amplify Web UI
* Pick an `Environment`
* Add a new `API Service`

  * Select `OpenAPI 3` as `Specification Type`
  * Follow Web UI Wizzard
  * Add all of the following `Attributes`

  ========================== ================================ ===================================
  Name                       Value                            Description
  ========================== ================================ ===================================
  solace-queue-require       true                             Enables queue provisioning
  solace-queue-accesstype    ( exclusive | non-exclusive )        Access mode for the queue
  solace-queue-maxttl        min: 0, max: 9007199254740991     Retention policy for messages on the queue, in seconds
  solace-queue-maxspoolusage min: 0, max: 9007199254740991     The maximum message spool usage allowed by the Queue, in megabytes (MB)

                             max depending on deployed        A value of 0 only allows spooling of the last message received and disables quota checking

                             Solace PubSub+ Broker
  ========================== ================================ ===================================


