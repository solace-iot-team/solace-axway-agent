Prerequisites
=============


Amplify Platform
----------------

Create Public/Private Key Pair as `PEM`-files
+++++++++++++++++++++++++++++++++++++++++++++

*Solace Axway Agent for Async API-Management* authenticates itself against *Amplify API server* by a certificate.

A certificate can get created by Amplify platform during registration of a Amplify Service Account or by utilizing 3rd party tooling:

::

  openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

Create Amplify Service Account
++++++++++++++++++++++++++++++

* Sign in to the `Amplify Platform <https://platform.axway.com>`_.

* Click on the `User & Org` menu and select `Organization`.

* Click the `Service Accounts` tab from the left navigation.

* Click the  `+`  `Service Account` button in the upper-right corner.

* Enter the service account name and optionally add a description.

* In the Authentication section, select `Client Certificate` to authenticate the service account.

  * Select `Provide public key` to upload your public key for your certificate created in the previous step.

  * Or let Amplify create one and download both keys

* Click  `Save`.

.. note::
  Besides public and private keys the *`Client ID`* of the service account must get noted and provided during installation.
  `Client ID` is created by Amplify while adding a service account.


Solace Environment
------------------

*Solace Axway Agent for Async API-Management* communicates with Solace Platform via `Solace Platform API`.
More details about `Soalce Platform API` are described at GitHub `solace-iot-team/platform-api <https://github.com/solace-iot-team/platform-api>`

.. note::
  These details must get provided during installation:

  * URL of `Solace Platform API`

  * `admin` user and password

  * `Org-Admin` user and password


An *Organization* within `Solace Platform API` service with at least one *Solace-Environment* must be provisioned:

  * Option a: the name of the *Organization* is the same as Amplify `Environment`
  * Option b: arbitrary name of the *Organization* and configured `orgMapping` (see `CONNECTOR_ORGMAPPING` environment variable in sample) with the name of the *Organization*
  * The *Organization* must have at least one *Solace-Environment* and assigned `Protocols` (e.g. `mqtt` or `smf`) that will later get used in Amplify as `Endpoint`.

