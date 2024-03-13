// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gateway

import (
	"fmt"

	"istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/analysis"
	"istio.io/istio/pkg/config/analysis/analyzers/util"
	"istio.io/istio/pkg/config/analysis/msg"
	"istio.io/istio/pkg/config/resource"
	"istio.io/istio/pkg/config/schema/gvk"
)

type CertificateAnalyzer struct{}

var _ analysis.Analyzer = &CertificateAnalyzer{}

func (*CertificateAnalyzer) Metadata() analysis.Metadata {
	return analysis.Metadata{
		Name:        "gateway.CertificateAnalyzer",
		Description: "Checks a gateway certificate",
		Inputs: []config.GroupVersionKind{
			gvk.Gateway,
		},
	}
}

// Analyze implements analysis.Analyzer
func (gateway *CertificateAnalyzer) Analyze(context analysis.Context) {
	gatewayIndexByCert := initIndex(context)
	context.ForEach(gvk.Gateway, func(resource *resource.Instance) bool {
		gateway.analyzeDuplicateCertificate(resource, context, features.ScopeGatewayToNamespace, gatewayIndexByCert)
		return true
	})
}

func (gateway *CertificateAnalyzer) analyzeDuplicateCertificate(currentResource *resource.Instance, context analysis.Context, scopeGatewayToNamespace bool, gatewayIndexByCert map[string][]*resource.Instance) {
	currentGateway := currentResource.Message.(*v1alpha3.Gateway)
	currentGatewayFullName := currentResource.Metadata.FullName

	for _, currentServer := range currentGateway.Servers {
		if currentServer.Tls == nil {
			continue
		}
		key := tlsSettingsToString(currentServer.Tls)
		gateways := gatewayIndexByCert[key]
		for _, gatewayInstance := range gateways {
			// ignore matching the same exact gateway
			if currentGatewayFullName == gatewayInstance.Metadata.FullName {
				continue
			}

			if gatewaySelectorMatches(currentResource, gatewayInstance, scopeGatewayToNamespace) {
				gatewayNames := []string{currentGatewayFullName.String(), gatewayInstance.Metadata.FullName.String()}
				message := msg.NewGatewayDuplicateCertificate(currentResource, gatewayNames)

				if line, ok := util.ErrorLine(currentResource, util.MetadataName); ok {
					message.Line = line
				}

				context.Report(gvk.Gateway, message)
			}
		}
	}
}

func gatewaySelectorMatches(currentGW, gatewayR *resource.Instance, gwScope bool) bool {
	// if scopeToNamespace true, ignore gateways from other namespace
	if gwScope {
		if currentGW.Metadata.FullName.Namespace != gatewayR.Metadata.FullName.Namespace {
			return false
		}
	}

	currentGateway := currentGW.Message.(*v1alpha3.Gateway)
	// if current gateway selector is empty, match all gateway
	if len(currentGateway.Selector) == 0 {
		return true
	}

	gateway := gatewayR.Message.(*v1alpha3.Gateway)
	// if current gateway selector is subset of other gateway selector
	return selectorSubset(currentGateway.Selector, gateway.Selector)
}

func selectorSubset(selectorX, selectorY map[string]string) bool {
	var count int

	for keyX, valueX := range selectorX {
		for keyY, valueY := range selectorY {
			if keyX == keyY {
				// if have same key but different value
				// mean selectorX is not subset of selectorY
				if valueX != valueY {
					return false
				}
				// if key and value is same
				// increase the counting
				count++
			}
		}
	}

	// if total counting is not same with the length
	// of selectorX, selectorX is not subset of selectorY
	return count == len(selectorX)
}

// create index of gateway by tls credentials
func initIndex(c analysis.Context) map[string][]*resource.Instance {
	gatewayIndexByCert := make(map[string][]*resource.Instance)
	c.ForEach(gvk.Gateway, func(resource *resource.Instance) bool {
		gateway := resource.Message.(*v1alpha3.Gateway)
		for _, server := range gateway.Servers {
			if server.Tls == nil {
				continue
			}
			key := tlsSettingsToString(server.Tls)
			gatewayIndexByCert[key] = append(gatewayIndexByCert[key], resource)
		}
		return true
	})
	return gatewayIndexByCert
}

func tlsSettingsToString(tls *v1alpha3.ServerTLSSettings) string {
	return fmt.Sprintf("%s-%s-%s", tls.CredentialName, tls.ServerCertificate, tls.PrivateKey)
}
