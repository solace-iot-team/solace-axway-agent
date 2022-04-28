Axway Amplify Configuration
===========================

AsyncAPIs with Webhooks
-----------------------

To enable provisioning of webhooks in Solace PubSub+ Brokers this specific `Attribute` must get provided during creation of a Axway Amplify Service:

.. note::
  Please be aware of that `Attributes` etc. can *not* get changed, added or removed for an `API Service` after creation of this service through the Web UI.

* Open `Topology` section in Axway Amplify Web UI
* Pick an `Environment`
* Add a new `API Service`
  * Select `OpenAPI 3` as `Specification Type`
  * Follow Web UI Wizzard
  * Add `Attribute` (key/value)
    * Key: `solace-webhook-enabled`
    * Value: `true`

AsyncAPIs with Queues
---------------------

TODO