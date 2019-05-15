# Vault Exporter

Export [Hashicorp Vault](https://github.com/hashicorp/vault) health and telemtry metrics to [Prometheus](https://github.com/prometheus/prometheus).

## Exported Health Metrics

| Metric | Meaning | Labels |
| ------ | ------- | ------ |
| vault_up | Was the last query of Vault successful, | |
| vault_initialized | Is the Vault initialised (according to this node). | |
| vault_sealed | Is the Vault node sealed. | |
| vault_standby | Is this Vault node in standby. | |
| vault_replication_dr_primary | Is this Vault node a primary disaster recovery replica. | |
| vault_replication_dr_secondary | Is this Vault node a secondary disaster recovery replica. | |
| vault_replication_performance_primary | Is this Vault node a primary performance replica. | |
| vault_replication_performance_secondary | Is this Vault node a secondary performance replica. | |
| vault_info | Various info about the Vault node. | version, cluster_name, cluster_id |

[Vault Health](https://www.vaultproject.io/api/system/health.html)

## Export Telemetry Metrics
[Vault Telemetry Metrics](https://www.vaultproject.io/api/system/metrics.html)

## Environment variables

Note that environment variables can be overwritten by flags.

* `VAULT_ADDR` – Sets the address of Vault in the client.
* `VAULT_TOKEN` – Token is the access token used by client.

## Run Docker Manually
```
  docker run \
  -e VAULT_ADDR="[Vault Address]" \
  -e VAULT_TOKEN="[Vault Token]" \
  -p 9101:9101 travix/vault-exporter
```