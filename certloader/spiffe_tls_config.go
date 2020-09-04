/*-
 * Copyright 2019 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package certloader

import (
	"context"
	"crypto/tls"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

type spiffeTLSConfigSource struct {
	source *workloadapi.X509Source
	log  Logger
}

type spiffeLogger struct {
	log Logger
}

func (l spiffeLogger) Debugf(format string, args ...interface{}) {
	l.log.Printf("(spiffe) [DEBUG]: "+format, args...)
}

func (l spiffeLogger) Infof(format string, args ...interface{}) {
	l.log.Printf("(spiffe) [INFO]: "+format, args...)
}

func (l spiffeLogger) Warnf(format string, args ...interface{}) {
	l.log.Printf("(spiffe) [WARN]: "+format, args...)
}

func (l spiffeLogger) Errorf(format string, args ...interface{}) {
	l.log.Printf("(spiffe) [ERROR]: "+format, args...)
}

func TLSConfigSourceFromWorkloadAPI(addr string, log Logger) (TLSConfigSource, error) {
	ctx := context.Background()
	clientOptions := workloadapi.WithClientOptions(
				workloadapi.WithAddr(addr),
				workloadapi.WithLogger(spiffeLogger{log: log}))
	source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		return nil, err
	}

	// TODO: provide a way to close the source on graceful shutdown
	return &spiffeTLSConfigSource{
		source: source,
		log:  log,
	}, nil
}

func (s *spiffeTLSConfigSource) Reload() error {
	// The config returned by the workload TLSConfig maintains itself. Nothing
	// to do here.
	return nil
}

func (s *spiffeTLSConfigSource) CanServe() bool {
	return true
}

func (s *spiffeTLSConfigSource) GetClientConfig(base *tls.Config) (TLSClientConfig, error) {
	return s.newConfig(base)
}

func (s *spiffeTLSConfigSource) GetServerConfig(base *tls.Config) (TLSServerConfig, error) {
	return s.newConfig(base)
}

func (s *spiffeTLSConfigSource) Close() error {
	return s.source.Close()
}

func (s *spiffeTLSConfigSource) newConfig(base *tls.Config) (*spiffeTLSConfig, error) {
	s.log.Printf("waiting for initial SPIFFE Workload API update...")
	s.log.Printf("received SPIFFE Workload API update.")
	return &spiffeTLSConfig{
		base: base,
		source: s.source,
	}, nil
}

type spiffeTLSConfig struct {
	base *tls.Config
	source *workloadapi.X509Source
}

func (c *spiffeTLSConfig) GetClientConfig() *tls.Config {
	config := c.base.Clone()
	// Build a TSL config that takes care of wrapping the incoming certificate
	// and do all the neccessery verifications. 
	tlsconfig.HookMTLSClientConfig(config, c.source, c.source, tlsconfig.AuthorizeAny())
	return config
}

func (c *spiffeTLSConfig) GetServerConfig() *tls.Config {
	config := c.base.Clone()
	svid := &x509svid.SVID{}
	tlsconfig.HookMTLSServerConfig(config, svid, c.source, tlsconfig.AuthorizeAny())
	return config
}

