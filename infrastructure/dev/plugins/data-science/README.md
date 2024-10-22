# Running the Script

Enter the information below as environment variable:

```bash
export org_name_plain=aws-org
export cloud_instance_alias=aws-dev-01
export cloud_instance=aws-dev-01-5f6s87
export region_plain=aws-eu-east-2
export root_domain=robolaunch.internal
```

## Parameters

|        Parameter       |   Type   | Definition                                                                                                                   | Example Value(s)          |
|:----------------------:|:--------:|------------------------------------------------------------------------------------------------------------------------------|---------------------------|
|    `org_name_plain`    | Required | Organization name without  org_ prefix, available in node labels (of any compute plane).                                     | `robolaunch-ankara`       |
| `cloud_instance_alias` | Required | Selected cloud instance name, can be identical with the `cloud_instance_alias` in on premise deployments.                    | `ankara-instance-1`       |
|    `cloud_instance`    | Required | Selected cloud instance alias, can be identical with the `cloud_instance` in on premise deployments.                         | `ankara-instance-1-kwefj` |
|     `region_plain`     | Required | Region name, available in node labels.                                                                                       | `ankara`                  |
|      `root_domain`     | Required | Root domain of the platform, eg. `robolaunch.internal` if the Keycloak address is `robolaunch-identity.robolaunch.internal`. | `robolaunch.internal`     |

## Artifacts

Artifacts are available under [releases section of this repository](https://github.com/robolaunch/on-premise/releases).

## Versions

Versions for artifacts and other components are fetched from [`platform.yaml`](https://raw.githubusercontent.com/robolaunch/robolaunch/main/platform.yaml).