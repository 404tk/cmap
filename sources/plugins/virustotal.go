package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

type VirusTotal struct{}

func (f VirusTotal) Name() string {
	return "virustotal"
}

type vtResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

// QuerySubdomain 子域名收集
func (f VirusTotal) QuerySubdomain(ctx context.Context, session *sources.Session, domain string) ([]string, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}

	req := &sources.Req{
		Schema:   "https",
		Endpoint: "www.virustotal.com",
		Path:     fmt.Sprintf("/api/v3/domains/%s/subdomains", domain),
		Method:   "GET",
		Header:   map[string]string{"x-apikey": *apikey},
		Query:    "limit=40",
	}

	res := make(map[string]struct{})
	var lastErr error

	for {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		request, err := req.Request()
		if err != nil {
			lastErr = err
			break
		}
		resp, err := session.Do(request, f.Name())
		if err != nil {
			lastErr = err
			break
		}

		var vtResp vtResponse
		if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
			resp.Body.Close()
			lastErr = err
			break
		}
		resp.Body.Close()

		if vtResp.Error.Code != "" && vtResp.Error.Code != "NotFoundError" {
			lastErr = fmt.Errorf("API error: %s", vtResp.Error.Code)
			break
		}

		for _, r := range vtResp.Data {
			sub := r.ID
			if len(sub) > 0 && sub != domain && strings.HasSuffix(sub, "."+domain) {
				res[sub] = struct{}{}
			}
		}

		// 翻页
		if vtResp.Links.Next == "" {
			break
		}
		u, err := url.Parse(vtResp.Links.Next)
		if err != nil {
			lastErr = err
			break
		}
		req.Query = u.Query().Encode()
	}

done:
	result := make([]string, 0, len(res))
	for k := range res {
		result = append(result, k)
	}
	return result, lastErr
}

// QueryAsset 不支持资产测绘
func (f VirusTotal) QueryAsset(ctx context.Context, session *sources.Session, query interface{}) (chan sources.Result, error) {
	return nil, nil
}

// VerifyKeys 验证 VirusTotal API 密钥
func (f VirusTotal) VerifyKeys(session *sources.Session) []config.KeyStatus {
	keys := config.GetKeys(f.Name())
	if len(keys) == 0 {
		return nil
	}

	results := make([]config.KeyStatus, 0, len(keys))
	for i, key := range keys {
		// VirusTotal 限速 4 req/min
		if i > 0 {
			time.Sleep(15 * time.Second)
		}
		status := config.KeyStatus{Key: maskKey(key)}

		req := &sources.Req{
			Schema:   "https",
			Endpoint: "www.virustotal.com",
			Path:     fmt.Sprintf("/api/v3/users/%s", key),
			Method:   "GET",
			Header:   map[string]string{"x-apikey": key},
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

		type vtUserInfo struct {
			Data struct {
				Attributes struct {
					Quotas struct {
						APIRequestsDaily struct {
							Used    int64 `json:"used"`
							Allowed int64 `json:"allowed"`
						} `json:"api_requests_daily"`
					} `json:"quotas"`
				} `json:"attributes"`
			} `json:"data"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		var info vtUserInfo
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			resp.Body.Close()
			status.Error = err
			results = append(results, status)
			continue
		}
		resp.Body.Close()

		if info.Error.Code != "" {
			status.Error = fmt.Errorf("%s", info.Error.Code)
			results = append(results, status)
			continue
		}

		status.Valid = true
		quota := info.Data.Attributes.Quotas.APIRequestsDaily
		status.Credits = quota.Allowed - quota.Used
		status.Info = fmt.Sprintf("Daily: %d/%d", quota.Used, quota.Allowed)
		results = append(results, status)
	}
	return results
}

func init() {
	registerPlugin("virustotal", VirusTotal{})
}
