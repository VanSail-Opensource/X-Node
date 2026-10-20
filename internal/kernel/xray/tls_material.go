package xray

import (
	"crypto/tls"
	"errors"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	nativetls "github.com/xtls/xray-core/transport/internet/tls"
)

func validateTLSMaterial(settings *serial.TypedMessage) error {
	obj, e := settings.GetInstance()
	if e != nil {
		return errors.New("invalid receiver settings")
	}
	receiver, ok := obj.(*proxyman.ReceiverConfig)
	if !ok || receiver.StreamSettings == nil {
		return nil
	}
	for _, raw := range receiver.StreamSettings.SecuritySettings {
		obj, e := raw.GetInstance()
		if e != nil {
			return errors.New("invalid security settings")
		}
		config, ok := obj.(*nativetls.Config)
		if !ok {
			continue
		}
		for _, certificate := range config.Certificate {
			if certificate.Usage == nativetls.Certificate_ENCIPHERMENT {
				if _, e = tls.X509KeyPair(certificate.Certificate, certificate.Key); e != nil {
					return errors.New("invalid TLS certificate or private key pair")
				}
			}
		}
	}
	return nil
}
