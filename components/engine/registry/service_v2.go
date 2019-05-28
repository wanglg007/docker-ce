package registry // import "github.com/docker/docker/registry"

import (
	"net/url"
	"strings"

	"github.com/docker/go-connections/tlsconfig"
)

func (s *DefaultService) lookupV2Endpoints(hostname string) (endpoints []APIEndpoint, err error) {
	tlsConfig := tlsconfig.ServerDefault()
	if hostname == DefaultNamespace || hostname == IndexHostname {				//如果是官方的 docker.io 或者 index.docker.io
		// v2 mirrors
		for _, mirror := range s.config.Mirrors {
			if !strings.HasPrefix(mirror, "http://") && !strings.HasPrefix(mirror, "https://") {
				mirror = "https://" + mirror
			}
			mirrorURL, err := url.Parse(mirror)
			if err != nil {
				return nil, err
			}
			mirrorTLSConfig, err := s.tlsConfigForMirror(mirrorURL)
			if err != nil {
				return nil, err
			}
			endpoints = append(endpoints, APIEndpoint{
				URL: mirrorURL,
				// guess mirrors are v2
				Version:      APIVersion2,
				Mirror:       true,
				TrimHostname: true,
				TLSConfig:    mirrorTLSConfig,
			})
		}
		// v2 registry
		endpoints = append(endpoints, APIEndpoint{
			URL:          DefaultV2Registry,
			Version:      APIVersion2,
			Official:     true,
			TrimHostname: true,
			TLSConfig:    tlsConfig,
		})

		return endpoints, nil
	}

	ana := allowNondistributableArtifacts(s.config, hostname)

	tlsConfig, err = s.tlsConfig(hostname)
	if err != nil {
		return nil, err
	}

	endpoints = []APIEndpoint{					//hostname的https v2请求
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   hostname,
			},
			Version: APIVersion2,
			AllowNondistributableArtifacts: ana,
			TrimHostname:                   true,
			TLSConfig:                      tlsConfig,
		},
	}

	if tlsConfig.InsecureSkipVerify {			//加上这个配置这允许 http方式访问
		endpoints = append(endpoints, APIEndpoint{
			URL: &url.URL{
				Scheme: "http",
				Host:   hostname,
			},
			Version: APIVersion2,
			AllowNondistributableArtifacts: ana,
			TrimHostname:                   true,
			// used to check if supposed to be secure via InsecureSkipVerify
			TLSConfig: tlsConfig,
		})
	}

	return endpoints, nil
}
