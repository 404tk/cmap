package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

type AlienVault struct{}

func (f AlienVault) Name() string {
	return "alienvault"
}

// QuerySubdomain 子域名收集
func (f AlienVault) QuerySubdomain(ctx context.Context, session *sources.Session, domain string) (chan string, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}

	results := make(chan string)
	go func() {
		defer close(results)

		req := &sources.Req{
			Schema:   "https",
			Endpoint: "otx.alienvault.com",
			Path:     fmt.Sprintf("/api/v1/indicators/domain/%s/passive_dns", domain),
			Method:   "GET",
			Header:   map[string]string{"X-OTX-API-KEY": *apikey},
		}

		request, err := req.Request()
		if err != nil {
			return
		}

		resp, err := session.Do(request, f.Name())
		if err != nil {
			return
		}
		defer resp.Body.Close()

		type avResponse struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}
		var avResp avResponse
		if err := json.NewDecoder(resp.Body).Decode(&avResp); err != nil {
			return
		}

		seen := make(map[string]struct{})
		for _, r := range avResp.PassiveDNS {
			select {
			case <-ctx.Done():
				return
			default:
			}
			sub := r.Hostname
			if strings.HasSuffix(sub, "."+domain) {
				if _, ok := seen[sub]; !ok {
					seen[sub] = struct{}{}
					results <- sub
				}
			}
		}
	}()

	return results, nil
}

// QueryAsset 不支持资产测绘
func (f AlienVault) QueryAsset(ctx context.Context, session *sources.Session, query interface{}) (chan sources.Result, error) {
	return nil, nil
}

// VerifyKeys 验证 AlienVault API 密钥
func (f AlienVault) VerifyKeys(session *sources.Session) []config.KeyStatus {
	keys := config.GetKeys(f.Name())
	if len(keys) == 0 {
		return nil
	}

	results := make([]config.KeyStatus, 0, len(keys))
	for _, key := range keys {
		status := config.KeyStatus{Key: maskKey(key)}

		req := &sources.Req{
			Schema:   "https",
			Endpoint: "otx.alienvault.com",
			Path:     "/api/v1/user/me",
			Method:   "GET",
			Header:   map[string]string{"X-OTX-API-KEY": key},
		}

		request, err := req.Request()
		if err != nil {
			status.Error = err
			results = append(results, status)
			continue
		}

		resp, err := session.Do(request, f.Name())
		if err != nil {
			status.Error = err
			results = append(results, status)
			continue
		}

		type avUserInfo struct {
			Username       string `json:"username"`
			PulseCount     int    `json:"pulse_count"`
			IndicatorCount int    `json:"indicator_count"`
			Error          string `json:"error"`
		}
		var info avUserInfo
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			resp.Body.Close()
			status.Error = err
			results = append(results, status)
			continue
		}
		resp.Body.Close()

		if info.Error != "" {
			status.Error = fmt.Errorf("%s", info.Error)
			results = append(results, status)
			continue
		}

		status.Valid = true
		status.Info = fmt.Sprintf("%s, Pulses: %d, Indicators: %d",
			info.Username, info.PulseCount, info.IndicatorCount)
		results = append(results, status)
	}
	return results
}

func init() {
	registerPlugin("alienvault", AlienVault{})
}
