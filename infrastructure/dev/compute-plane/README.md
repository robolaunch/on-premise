# Running the Script

Enter the information below as environment variable:

```bash
export org_name_plain=aws-org
export cloud_instance_alias=aws-dev-01
export cloud_instance=aws-dev-01-5f6s87
export region_plain=aws-eu-east-2
export identity_subdomain=aws-robolaunch-server
export root_domain=robolaunch.internal
export org_client_secret=lMVe8sMXCdv6KxOTwHrVcJon9r5kRyKy
export github_pat="<GITHUB-PERSONAL-ACCESS-TOKEN>"
# optional parameters
export self_signed_cert=true
export mig_strategy=mixed
export available_mig_instance=mig-1g.6gb
export tz_continent=Europe
export tz_city=Istanbul
export control_plane_host_entry="<IP>   <ENTRIES>"
export compute_plane_host_entry="<IP>   <ENTRIES>"
export control_compute_plane_host_entry="<IP>   <ENTRIES>"
```

## Parameters


|              Parameter             |   Type   | Definition                                                                                                                                               | Example Value(s)                                                                                                                                                                                 |
|:----------------------------------:|:--------:|----------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|          `org_name_plain`          | Required | Organization name without  org_ prefix, available in node labels (of any compute plane).                                                                 | `robolaunch-ankara`                                                                                                                                                                              |
|       `cloud_instance_alias`       | Required | Selected cloud instance name, can be identical with the `cloud_instance_alias` in on premise deployments.                                                | `ankara-instance-1`                                                                                                                                                                              |
|          `cloud_instance`          | Required | Selected cloud instance alias, can be identical with the `cloud_instance` in on premise deployments.                                                     | `ankara-instance-1-kwefj`                                                                                                                                                                        |
|           `region_plain`           | Required | Region name, available in node labels.                                                                                                                   | `ankara`                                                                                                                                                                                         |
|        `identity_subdomain`        | Required | Keycloak subdomain, eg. `robolaunch-identity` if the Keycloak address is `robolaunch-identity.example.com` or `robolaunch-identity.robolaunch.internal`. | `robolaunch-identity`                                                                                                                                                                            |
|            `root_domain`           | Required | Root domain of the platform, eg. `robolaunch.internal` if the Keycloak address is `robolaunch-identity.robolaunch.internal`.                             | `robolaunch.internal`                                                                                                                                                                            |
|         `org_client_secret`        | Required | OIDC client secret, available in Keycloak UI robo-realm → Clients → gatekeeper → Credentials → Client Secret.                                            | `T5XzUGlIb42fGJudrvIWJUFBSGOVYLdk`                                                                                                                                                               |
|            `github_pat`            | Required | GitHub personal access token for fetching the artifacts, must be authorized to R+W for all of the Github resources.                                      | `ghp_25V0boV87taGKuI9XahwgZ9V6P25JbsCm2Mz`                                                                                                                                                       |
|         `self_signed_cert`         | Optional | Whether the certificates are self-signed, or not.                                                                                                        | `true` or `false`                                                                                                                                                                                |
|           `mig_strategy`           | Optional | MIG strategy, `mixed` is used in compute planes, do not set if the GPU is not MIG-capable.                                                               | `mixed` or `none` or `single`                                                                                                                                                                    |
|      `available_mig_instance`      | Optional | MIG instance type, do not set if the GPU is not MIG-capable.                                                                                             | `mig-2g.20gb` or any other available configuration based on available MIG instances.                                                                                                             |
|           `tz_continent`           | Optional | Continent for the timezone in environments.                                                                                                              | `Europe`                                                                                                                                                                                         |
|              `tz_city`             | Optional | City for the timezone in environments.                                                                                                                   | `Istanbul`                                                                                                                                                                                       |
|     `control_plane_host_entry`     | Optional | Host entries for the control plane services, used if it’s a simple compute plane setup.                                                                  | `18.159.141.7    eskisehir-identity.robolaunch.internal eskisehir-storage.robolaunch.internal eskisehir-backend.robolaunch.internal eskisehir-ui.robolaunch.internal`                            |
|     `compute_plane_host_entry`     | Optional | Host entry for the same compute plane, used if it’s a simple compute plane setup.                                                                        | `3.124.201.74    esk-02.robolaunch.internal`                                                                                                                                                     |
| `control_compute_plane_host_entry` | Optional | Host entries for the control plane services, used if it’s a one cluster (control + compute plane) setup.                                                 | `18.159.141.7    esk-01.robolaunch.internal eskisehir-identity.robolaunch.internal eskisehir-storage.robolaunch.internal eskisehir-backend.robolaunch.internal eskisehir-ui.robolaunch.internal` |