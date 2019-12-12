package main

import (
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"io/ioutil"
	"fmt"
	"time"
	"os"
	"strings"
	vault_api "github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"crypto/tls"

)

var (
	listenAddress = kingpin.Flag("web.listen-address",
		"Address to listen on for web interface and telemetry.").
		Default(":9101").String()
	metricsPath = kingpin.Flag("web.telemetry-path",
		"Path under which to expose metrics.").
		Default("/metrics").String()
	vaultCACert = kingpin.Flag("vault-tls-cacert",
		"The path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate.").String()
	vaultClientCert = kingpin.Flag("vault-tls-client-cert",
		"The path to the certificate for Vault communication.").String()
	vaultClientKey = kingpin.Flag("vault-tls-client-key",
		"The path to the private key for Vault communication.").String()
	sslInsecure = kingpin.Flag("insecure-ssl",
		"Set SSL to ignore certificate validation.").
		Default("false").Bool()
)
var (
	version   string
	branch    string
	revision  string
	buildDate string
	goVersion = runtime.Version()
)

const (
	namespace = "vault"
)

type VaultClient struct {
	client *vault_api.Client
}

// NewExporter returns an initialized Exporter.
func NewVaultClient() (*VaultClient, error) {
	vaultConfig := vault_api.DefaultConfig()

	if *sslInsecure {
		tlsconfig := &vault_api.TLSConfig{
			Insecure: true,
		}
		err := vaultConfig.ConfigureTLS(tlsconfig)
		if err != nil {
			return nil, err
		}
	}

	if *vaultCACert != "" || *vaultClientCert != "" || *vaultClientKey != "" {

		tlsconfig := &vault_api.TLSConfig{
			CACert:     *vaultCACert,
			ClientCert: *vaultClientCert,
			ClientKey:  *vaultClientKey,
			Insecure:   *sslInsecure,
		}
		err := vaultConfig.ConfigureTLS(tlsconfig)
		if err != nil {
			return nil, err
		}
	}

	client, err := vault_api.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	return &VaultClient{
		client: client,
	}, nil
}

func bool2float(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Collect fetches the stats from configured Vault and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *VaultClient) getVaultHealth() (string) {
	health, err := e.client.Sys().Health()
	var b strings.Builder
	if err != nil {
		fmt.Fprintf(&b, "vault_up %v", 0)
	}
	fmt.Fprintf(&b, "vault_up %v", 1)
	fmt.Fprintf(&b, "\nvault_initialized %v", bool2float(health.Initialized))
	fmt.Fprintf(&b, "\nvault_sealed %v", bool2float(health.Sealed))
	fmt.Fprintf(&b, "\nvault_standby %v", bool2float(health.Standby))

	if health.ReplicationDRMode == "disabled" {
		fmt.Fprintf(&b, "\nvault_replication_dr_primary %v", 0)
		fmt.Fprintf(&b, "\nvault_replication_dr_secondary %v", 0)

	 } else if health.ReplicationDRMode == "primary" {
		fmt.Fprintf(&b, "\nvault_replication_dr_primary %v", 1)
		fmt.Fprintf(&b, "\nvault_replication_dr_secondary %v", 0)
	 } else if health.ReplicationDRMode == "secondary" {
		fmt.Fprintf(&b, "\nvault_replication_dr_primary %v", 0)
		fmt.Fprintf(&b, "\nvault_replication_dr_secondary %v", 1)
	}

	if health.ReplicationPerformanceMode == "disabled" {
		fmt.Fprintf(&b, "\nvault_replication_performance_primary %v", 0)
		fmt.Fprintf(&b, "\nvault_replication_performance_secondary %v", 0)
	} else if health.ReplicationPerformanceMode == "primary" {
		fmt.Fprintf(&b, "\nvault_replication_performance_primary %v", 1)
		fmt.Fprintf(&b, "\nvault_replication_performance_secondary %v", 0)
	} else if health.ReplicationPerformanceMode == "secondary" {
		fmt.Fprintf(&b, "\nvault_replication_performance_primary %v", 0)
		fmt.Fprintf(&b, "\nvault_replication_performance_secondary %v", 1)
	}
	fmt.Fprintf(&b, "\nvault_info{cluster_id=\"%v\",cluster_name=\"%v\",version=\"%v\"} %v",health.ClusterID, health.ClusterName,health.Version, 1)
	return b.String()
}

func ServeVaultMetrics(w http.ResponseWriter, r *http.Request) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		log.Fatal().Msg("VAULT_ADDR is required. Please set VAULT_ADDR environment variable to your Vault address.")
	}

	vaultToken := os.Getenv("VAULT_TOKEN")
	if vaultToken == "" {
		log.Fatal().Msg("VAULT_TOKEN is required. Please set VAULT_TOKEN environment variable to your Vault token.")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *sslInsecure},
	}
	var httpClient = &http.Client{
		Transport: tr,
		Timeout: time.Second * 10,
	}
    url := fmt.Sprintf("%v/v1/sys/metrics", vaultAddr)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil{
        log.Fatal().Err(err)
	}

	var bearer = "Bearer " + vaultToken

	req.Header.Add("Authorization", bearer)

	q := req.URL.Query()
	q.Add("format", "prometheus")
	req.URL.RawQuery = q.Encode()

	response, err := httpClient.Do(req)

	defer response.Body.Close()

    responseData, err := ioutil.ReadAll(response.Body)
    if err != nil {
        log.Fatal().Err(err)
    }

	telemetryMetrics := string(responseData)
	vaultClient, err := NewVaultClient()

	if err != nil {
        log.Fatal().Err(err)
	}

	health := vaultClient.getVaultHealth()
	fmt.Fprint(w, telemetryMetrics, health)
}

func init() {
}

func main() {
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	// log as severity for stackdriver logging to recognize the level
	zerolog.LevelFieldName = "severity"

	// set some default fields added to all logs
	log.Logger = zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "vault-exporter").
		Str("version", version).
		Logger()

		// log startup message
	log.Info().
		Str("branch", branch).
		Str("revision", revision).
		Str("buildDate", buildDate).
		Str("goVersion", goVersion).
		Msg("Starting vault exporter...")

	log.Info().Msgf("Listening on", *listenAddress)

	http.HandleFunc(*metricsPath, ServeVaultMetrics)
    if err := http.ListenAndServe(*listenAddress, nil); err != nil {
        log.Fatal().Err(err).Msg("Starting vault-exporter listener failed")
    }
}
