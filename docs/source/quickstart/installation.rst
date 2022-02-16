Installation
============


.. warning::
  UNDER CONSTRUCTION

*Solace Axway Agent for Async API-Management* is typically executed as Docker container.

Releases of the agent are published to Docker Hub and are located at `solaceiotteam/solace-axway-agent <https://hub.docker.com/repository/docker/solaceiotteam/solace-axway-agent>`_ .


Configuration of `solace-axway-agent` Docker container
++++++++++++++++++++++++++++++++++++++++++++++++++++++

The agent is getting configured by providing environment variables.

A documented sample of all environment variables is located at `.env.sample <https://github.com/solace-iot-team/solace-axway-agent/tree/main/sample>`_

* Solace-Axway-Agent is executed as user `AGENT` (uid=9999,gid=9999)
* Path `/opt/agent` is read and writeable for user AGENT

Two options are available to provide the key-pair (private_key.pem and public_key.pem) for Amplify:

* **Option a) make key-pair accessible through file-mount and point Solace-Axway-Agent to this mount point**

    * `CENTRAL_AUTH_PRIVATEKEY=/path/to/private_key.pem` and `CENTRAL_AUTH_PRIVATEKEY=/path/to/public_key.pem`

    * `CENTRAL_AUTH_PRIVATEKEY_DATA` and `CENTRAL_AUTH_PUBLIC_DATA` **must not** be set

* **Option b) share key-pair as environment variable**

  ::

    # Path and Filename of Axway Central Service Account private key as PEM
    CENTRAL_AUTH_PRIVATEKEY=/path/to/private_key.pem
    # Optional - PEM content as one line PEM
    CENTRAL_AUTH_PRIVATEKEY_DATA="-----BEGIN PRIVATE KEY-----\n ... \n-----END PRIVATE KEY-----\n"
    #publickey within Axway Central
    # Path and Filename of Axway Central Service Account public key as PEM
    CENTRAL_AUTH_PUBLICKEY=/path/to/public_key.pem
    # Optional - PEM content as one line PEM
    CENTRAL_AUTH_PUBLICKEY_DATA="-----BEGIN PUBLIC KEY-----\n ... \n-----END PUBLIC KEY-----\n"

  The agent first checks, if there are already key-files located at `CENTRAL_AUTH_PRIVATEKEY` or `CENTRAL_AUTH_PUBLICKEY` file location. If there are no keys at these
  locations the agent looks up if there are environment variables defined `CENTRAL_AUTH_PRIVATEKEY_DATA` or `CENTRAL_AUTH_PUBLICKEY_DATA` with the actual key-data.
  The agent writes a copy of the key-data to the key-files locations and continues by using the keys written to the files.

    * `/opt/agent` within the Docker container is writeable for SOLACE-AXWAY-AGENT

    *  as SOLACE-AXWAY-AGENT is not executed as ROOT the mount-paths for public-key and private-key must be writeable for NON-ROOT user (uid=9999, gid=9999)

      * it could be a security risk to mount a file system and let the agent write the public-key into this file mount.

.. note::
   To convert PEM files into environment variable format you can use the following command:
    ::

       awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' cert-name.pem




