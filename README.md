# grafana-registry

Component used to create dashboards in grafana dynamically and modify their permissions so that only the user that created them has access to them.

## API endpoints:

### /dashboards \[POST\]

Used to create dashboards of a certain deployment, identified by the label `monitoring_id`. Call must have a valid JWT in the Authorization header to identify the user. 
Once the user is identified through the JWT by connecting to the configured OIDC service configured, a set of dashboards is created in grafana for the provided `monitoring_id`. The dashboards' permissions are then modified so that only the authenticated user has access to them. In case the user is not registered in grafana, they are registered using the information stored in the JWT.

Payload:

```
{
    "deployment_label": <deployment_label>,
    "monitoring_id": <monitoring_id>"
}
```

Example:
```
curl 192.168.3.74:3001/dashboards -X POST -d '{"deployment_label":"test-sec","monitoring_id":"as54d5a-trvb2yh58-dsada9s5fd8f"}' -H'Content-Type: application/json' -H 'authorization: Bearer eyNhb...ZkwNwg'
```

### /dashboards \[DELETE\]

Used to remove dashboards of a certain deployment, identified by the label `monitoring_id`. Call must have a valid JWT in the Authorization header to identify the user. 
Once the user is identified through the JWT by connecting to the configured OIDC service configured, all the dashboards corresponding to that monitoring_id are deleted from grafana

Payload:

```
{
    "deployment_label": <deployment_label>,
    "monitoring_id": <monitoring_id>"
}
```

Example:
```
curl 192.168.3.74:3001/dashboards -X DELETE -d '{"deployment_label":"test-sec","monitoring_id":"as54d5a-trvb2yh58-dsada9s5fd8f"}' -H'Content-Type: application/json' -H 'authorization: Bearer eyNhb...ZkwNwg'
```

### /dashboards/deployment/\<monitoring_id\> \[GET\]

Used to retrieve the URLs of dashboards of a certain deployment, identified by the label `monitoring_id`. Call must have a valid JWT in the Authorization header to identify the user. 
Once the user is identified through the JWT by connecting to the configured OIDC service configured, if the user was the one that created the dashboards for the requested `monitoring_id`, a JSON object is returned with the URLs

Example request:
```
curl 192.168.3.74:3001/dashboards/deployment/as54d5a-trvb2yh58-dsada9s5fd8f -H 'authorization: Bearer eyNhb...ZkwNwg'
```

Example response:

```
{
     "node":"/d/tA-D4hznz/sodalite-node-exporters-test-sec",
     "pbs":"/d/4mxD42k7k/sodalite-pbs-exporters-test-sec",
     "slurm":"/d/slbv42knk/sodalite-slurm-exporters-test-sec"
}
```

### /dashboards/user \[GET\]

Used to retrieve the URLs of all the dashboards belonging to a certain user, identified by the valid JWT in the Authorization header. 
Once the user is identified through the JWT by connecting to the configured OIDC service configured, if the user has dashboards in the system, a JSON object is returned with the URLs.

Example request:
```
curl 192.168.3.74:3001/dashboards/user -H 'authorization: Bearer eyNhb...ZkwNwg'
```

Example response:

```
{
     "as54d5a-trvb2yh58-dsada9s5fd8f": {
         "node":"/d/tA-D4hznz/sodalite-node-exporters-test-sec",
         "pbs":"/d/4mxD42k7k/sodalite-pbs-exporters-test-sec",
         "slurm":"/d/slbv42knk/sodalite-slurm-exporters-test-sec"
     }
}
```


## Deployment


A docker image is provided to launch this conmponent in a container. Image can be found in [sodaliteh2020/grafana-registry](https://hub.docker.com/r/sodaliteh2020/grafana-registry/tags?page=1&ordering=last_updated)
Environment variables needed to configure the container:

- FLASK_RUN_PORT: Port on which the API will listen to requests. 
- OIDC_CLIENT_ID: Client name of the OIDC service.
- OIDC_CLIENT_SECRET: Client secret of the OIDC service.
- OIDC_INTROSPECTION_ENDPOINT: Endpoint of the service used to validate JWTs.
- GF_ADMIN_PW: Grafana admin password
- GF_ADMIN_USER: Grafana admin user
- GF_ADDRESS: Grafana address. "grafana" by default (in case the grafana instance is in a container in the same docker network)
- GF_PORT: Grafana port. 3000 by default.
- PROMETHEUS_ADDRESS: Prometheus address. "prometheus" by default (in case the prometheus instance is in a container in the same docker network)
- PROMETHEUS_PORT: Prometheus port. 9090 by default.