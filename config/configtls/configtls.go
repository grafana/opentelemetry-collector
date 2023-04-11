// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package configtls // import "go.opentelemetry.io/collector/config/configtls"

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sync"
	"time"
)

// We should avoid that users unknowingly use a vulnerable TLS version.
// The defaults should be a safe configuration
const defaultMinTLSVersion = tls.VersionTLS12

// Uses the default MaxVersion from "crypto/tls" which is the maximum supported version
const defaultMaxTLSVersion = 0

// TLSSetting exposes the common client and server TLS configurations.
// Note: Since there isn't anything specific to a server connection. Components
// with server connections should use TLSSetting.
type TLSSetting struct {
	// Path to the CA cert. For a client this verifies the server certificate.
	// For a server this verifies client certificates. If empty uses system root CA.
	// (optional)
	CAFile string `mapstructure:"ca_file"`

	// In memory PEM encoded cert. (optional)
	CAPem []byte `mapstructure:"ca_pem"`

	// Path to the TLS cert to use for TLS required connections. (optional)
	CertFile string `mapstructure:"cert_file"`

	// In memory PEM encoded TLS cert to use for TLS required connections. (optional)
	CertPem []byte `mapstructure:"cert_pem"`

	// Path to the TLS key to use for TLS required connections. (optional)
	KeyFile string `mapstructure:"key_file"`

	// In memory PEM encoded TLS key to use for TLS required connections. (optional)
	KeyPem []byte `mapstructure:"key_pem"`

	// MinVersion sets the minimum TLS version that is acceptable.
	// If not set, TLS 1.2 will be used. (optional)
	MinVersion string `mapstructure:"min_version"`

	// MaxVersion sets the maximum TLS version that is acceptable.
	// If not set, refer to crypto/tls for defaults. (optional)
	MaxVersion string `mapstructure:"max_version"`

	// ReloadInterval specifies the duration after which the certificate will be reloaded
	// If not set, it will never be reloaded (optional)
	ReloadInterval time.Duration `mapstructure:"reload_interval"`
}

// TLSClientSetting contains TLS configurations that are specific to client
// connections in addition to the common configurations. This should be used by
// components configuring TLS client connections.
type TLSClientSetting struct {
	// squash ensures fields are correctly decoded in embedded struct.
	TLSSetting `mapstructure:",squash"`

	// These are config options specific to client connections.

	// In gRPC when set to true, this is used to disable the client transport security.
	// See https://godoc.org/google.golang.org/grpc#WithInsecure.
	// In HTTP, this disables verifying the server's certificate chain and host name
	// (InsecureSkipVerify in the tls Config). Please refer to
	// https://godoc.org/crypto/tls#Config for more information.
	// (optional, default false)
	Insecure bool `mapstructure:"insecure"`
	// InsecureSkipVerify will enable TLS but not verify the certificate.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
	// ServerName requested by client for virtual hosting.
	// This sets the ServerName in the TLSConfig. Please refer to
	// https://godoc.org/crypto/tls#Config for more information. (optional)
	ServerName string `mapstructure:"server_name_override"`
}

// TLSServerSetting contains TLS configurations that are specific to server
// connections in addition to the common configurations. This should be used by
// components configuring TLS server connections.
type TLSServerSetting struct {
	// squash ensures fields are correctly decoded in embedded struct.
	TLSSetting `mapstructure:",squash"`

	// These are config options specific to server connections.

	// Path to the TLS cert to use by the server to verify a client certificate. (optional)
	// This sets the ClientCAs and ClientAuth to RequireAndVerifyClientCert in the TLSConfig. Please refer to
	// https://godoc.org/crypto/tls#Config for more information. (optional)
	ClientCAFile string `mapstructure:"client_ca_file"`
}

// certReloader is a wrapper object for certificate reloading
// Its GetCertificate method will either return the current certificate or reload from disk
// if the last reload happened more than ReloadInterval ago
type certReloader struct {
	// Path to the TLS cert
	CertFile string
	// Path to the TLS key
	KeyFile string
	// ReloadInterval specifies the duration after which the certificate will be reloaded.
	// If not set, it will never be reloaded. If CertFile isn't set, it will never be reloaded. (optional)
	ReloadInterval time.Duration
	nextReload     time.Time
	cert           *tls.Certificate
	lock           sync.RWMutex
}

func (c TLSSetting) newCertReloader(reloadInterval time.Duration) (*certReloader, error) {
	cert, err := c.loadCertificate()
	if err != nil {
		return nil, err
	}
	return &certReloader{
		CertFile:       c.CertFile,
		KeyFile:        c.KeyFile,
		ReloadInterval: reloadInterval,
		nextReload:     time.Now().Add(reloadInterval),
		cert:           &cert,
	}, nil
}

func (r *certReloader) GetCertificate() (*tls.Certificate, error) {
	now := time.Now()
	// Read locking here before we do the time comparison
	// If a reload is in progress this will block and we will skip reloading in the current
	// call once we can continue
	r.lock.RLock()
	if r.ReloadInterval != 0 && r.nextReload.Before(now) && r.CertFile != "" {
		// Need to release the read lock, otherwise we deadlock
		r.lock.RUnlock()
		r.lock.Lock()
		defer r.lock.Unlock()
		cert, err := tls.LoadX509KeyPair(r.CertFile, r.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS cert and key: %w", err)
		}
		r.cert = &cert
		r.nextReload = now.Add(r.ReloadInterval)
		return r.cert, nil
	}
	defer r.lock.RUnlock()
	return r.cert, nil
}

// loadTLSConfig loads TLS certificates and returns a tls.Config.
// This will set the RootCAs and Certificates of a tls.Config.
func (c TLSSetting) loadTLSConfig() (*tls.Config, error) {
	certPool, err := c.loadCertPool()
	if err != nil {
		return nil, err
	}

	var getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	var getClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)

	var certReloader *certReloader
	certReloader, err = c.newCertReloader(c.ReloadInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS cert and key: %w", err)
	}

	certReloader.lock.RLock()
	if certReloader.cert != nil {
		getCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return certReloader.GetCertificate() }
		getClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) { return certReloader.GetCertificate() }
	}
	certReloader.lock.RUnlock()

	minTLS, err := convertVersion(c.MinVersion, defaultMinTLSVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS min_version: %w", err)
	}
	maxTLS, err := convertVersion(c.MaxVersion, defaultMaxTLSVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS max_version: %w", err)
	}

	return &tls.Config{
		RootCAs:              certPool,
		GetCertificate:       getCertificate,
		GetClientCertificate: getClientCertificate,
		MinVersion:           minTLS,
		MaxVersion:           maxTLS,
	}, nil
}

func (c TLSSetting) loadCertPool() (*x509.CertPool, error) {
	// There is no need to load the System Certs for RootCAs because
	// if the value is nil, it will default to checking against th System Certs.
	var err error
	var certPool *x509.CertPool

	switch {
	case len(c.CAFile) != 0 && len(c.CAPem) != 0:
		return nil, fmt.Errorf("failed to load CA CertPool: CA File and PEM cannot both be provided")
	case len(c.CAFile) != 0:
		// Set up user specified truststore from file
		certPool, err = c.loadCertFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA CertPool File: %w", err)
		}
	case len(c.CAPem) != 0:
		// Set up user specified truststore from PEM
		certPool, err = c.loadCertPem(c.CAPem)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA CertPool PEM: %w", err)
		}
	}

	return certPool, nil
}

func (c TLSSetting) loadCertFile(caPath string) (*x509.CertPool, error) {
	caPEM, err := ioutil.ReadFile(filepath.Clean(caPath))
	if err != nil {
		return nil, fmt.Errorf("failed to load CA %s: %w", caPath, err)
	}

	return c.loadCertPem(caPEM)
}

func (c TLSSetting) loadCertPem(caPEM []byte) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA %s", caPEM)
	}
	return certPool, nil
}

func (c TLSSetting) loadCertificate() (tls.Certificate, error) {
	hasCertFile := len(c.CertFile) != 0
	hasCertPem := len(c.CertPem) != 0
	hasKeyFile := len(c.KeyFile) != 0
	hasKeyPem := len(c.KeyPem) != 0
	hasCert := hasCertFile || hasCertPem
	hasKey := hasKeyFile || hasKeyPem

	// Validate the incoming parameters.
	switch {
	case hasCert != hasKey:
		return tls.Certificate{}, fmt.Errorf("for auth via TLS, either both certificate and key must be supplied, or neither")
	case hasCertFile && !hasKeyFile:
		return tls.Certificate{}, fmt.Errorf("failed to load TLS cert file and key PEM: both must be provided as a file or both as a PEM")
	case !hasCertFile && hasKeyFile:
		return tls.Certificate{}, fmt.Errorf("failed to load TLS cert PEM and key file: both must be provided as a file or both as a PEM")
	case hasCertFile && hasCertPem:
		return tls.Certificate{}, fmt.Errorf("for auth via TLS, certificate file and PEM cannot both be provided")
	case hasKeyFile && hasKeyPem:
		return tls.Certificate{}, fmt.Errorf("for auth via TLS, key file and PEM cannot both be provided")
	}

	// If we don't have a cert, return the nil pointer.
	if !hasCert {
		return tls.Certificate{}, nil
	}

	// Add the tls cert to the certificates from the files or in memory PEM.
	var err error
	var certificate tls.Certificate
	if hasCertFile {
		certificate, err = tls.LoadX509KeyPair(filepath.Clean(c.CertFile), filepath.Clean(c.KeyFile))
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to load TLS cert and key files: %w", err)
		}
	} else {
		certificate, err = tls.X509KeyPair(c.CertPem, c.KeyPem)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to load TLS cert and key PEMs: %w", err)
		}
	}

	return certificate, err
}

// LoadTLSConfig loads the TLS configuration.
func (c TLSClientSetting) LoadTLSConfig() (*tls.Config, error) {
	if c.Insecure && c.CAFile == "" && len(c.CAPem) == 0 {
		return nil, nil
	}

	tlsCfg, err := c.TLSSetting.loadTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}
	tlsCfg.ServerName = c.ServerName
	tlsCfg.InsecureSkipVerify = c.InsecureSkipVerify
	return tlsCfg, nil
}

// LoadTLSConfig loads the TLS configuration.
func (c TLSServerSetting) LoadTLSConfig() (*tls.Config, error) {
	tlsCfg, err := c.loadTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}
	if c.ClientCAFile != "" {
		certPool, err := c.loadCertFile(c.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS config: failed to load client CA CertPool: %w", err)
		}
		tlsCfg.ClientCAs = certPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}

func convertVersion(v string, defaultVersion uint16) (uint16, error) {
	// Use a default that is explicitly defined
	if v == "" {
		return defaultVersion, nil
	}
	val, ok := tlsVersions[v]
	if !ok {
		return 0, fmt.Errorf("unsupported TLS version: %q", v)
	}
	return val, nil
}

var tlsVersions = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}
