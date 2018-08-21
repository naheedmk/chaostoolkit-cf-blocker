# chaostoolkit-cf-app-blocker
Plugin for chaostoolkit which blocks access to a cloud foundry application.

### Getting Started
In order to run the script, it will require that you have the
[Cloud Foundry CLI](https://docs.cloudfoundry.org/cf-cli/install-go-cli.html) installed and the
[BOSH CLI](https://bosh.io/docs/cli-v2-install/) installed. You will also need to be logged in to the Cloud Foundry CLI 
as a user with permission to access all apps which are to be targeted and logged in as an admin to the BOSH CLI. This is
because the script requires ssh access to the bosh vms.

Once the CLIs are ready, create (or modify the existing) configuration file.

- `bosh`: Information about the bosh cli and environment
    - `cmd`: The bosh-cli command.
    - `env`: The environment name for the cf deployment (`-e env`).
    - `cf-dep`: The cloud foundry deployment in the bosh environment.
    - `cfdot-dc`: The diego-cell to use for `cfdot` queries.
- `cf`: Information about the cf cli and environment
    - `cmd`: The cf-cli command.
- `container-port-whitelist`: List of node ports which should be ignored. These are the external ports on the
diego-cells.
- `service-whitelist`: List of service types which should be ignored. These must be the names displayed in the cf-cli
marketplace.


Sample config.yml 

```yaml
bosh:
  cmd: bosh2
  env: bosh-lite
  cf-dep: cf
  cfdot-dc: diego-cell/0
cf:
  cmd: cf
container-port-whitelist:
 - 22
 - 2222
host-port-whitelist: []
service-whitelist:
 - logger
```

### Using AppBlocker
```commandline
usage: cli.py [-h] (--block | --block-services | --unblock | --discover)
              [--config PATH] [--targeted PATH]
              org space app

Block Cloud Foundry Applications or their Services.

positional arguments:
  org               Cloud Foundry Organization the Application is in.
  space             Cloud Foundry Space the Application is in.
  app               Name of the application in Cloud Foundry.

optional arguments:
  -h, --help        show this help message and exit
  --block           Block access to the application.
  --block-services  Block the app from accessing its bound services.
  --unblock         Unblock the app and its services.
  --discover        Discover the application hosts and bound service
                    information.
  --config PATH     Specify an alternative config path.
  --targeted PATH   Specify an alternative storage location for targeted
                    applications and services.
```