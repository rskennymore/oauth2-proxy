package util

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

// GetSecretValue returns the value of the Secret from its source
func GetSecretValue(source *options.SecretSource) ([]byte, error) {
	switch {
	case len(source.Value) > 0 && source.FromEnv == "" && source.FromFile == "":
		return source.Value, nil
	case len(source.Value) == 0 && source.FromEnv != "" && source.FromFile == "":
		return []byte(os.Getenv(source.FromEnv)), nil
	case len(source.Value) == 0 && source.FromEnv == "" && source.FromFile != "":
		return os.ReadFile(source.FromFile)
	default:
		return nil, errors.New("secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile")
	}
}

// getSecretValue wraps GetSecretValue so that we can return an error if no
// source is provided.
func getSecretValue(src *options.SecretSource) ([]byte, error) {
	if src == nil {
		return nil, errors.New("no configuration provided")
	}
	return GetSecretValue(src)
}

// GetCertificate loads the certificate data from the TLS config.
func GetCertificate(opts *options.TLS) (tls.Certificate, error) {
	keyData, err := getSecretValue(opts.Key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not load key data: %v", err)
	}

	certData, err := getSecretValue(opts.Cert)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not load cert data: %v", err)
	}

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not parse certificate data: %v", err)
	}

	return cert, nil
}
