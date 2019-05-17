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
* `GCS_BUCKET_NAME` – The Google Cloud Storage Bucket where the vault root token is stored.
* `KMS_KEY_ID` - The Google Cloud KMS key ID used to encrypt and decrypt the vault root token.

## Run Docker Manually
You can download the code and compile the binary with Go. Alternatively, a
Docker container is available via the Docker Hub:

```
  docker run \
  -e VAULT_ADDR="[Vault Address]" \
  -e VAULT_TOKEN="[Vault Token]" \
  -p 9101:9101 travix/vault-exporter
```

### IAM &amp; Permissions

The `vault-exporter` service uses the official Google Cloud Golang SDK. This means
it supports the common ways of [providing credentials to GCP][cloud-creds].

To use this service, the service account must have the following minimum
scope(s):

```text
https://www.googleapis.com/auth/cloudkms
https://www.googleapis.com/auth/devstorage.read_write
```

Additionally, the service account must have the following minimum role(s):

```text
roles/cloudkms.cryptoKeyEncrypterDecrypter
roles/storage.objectAdmin OR roles/storage.legacyBucketWriter
```
