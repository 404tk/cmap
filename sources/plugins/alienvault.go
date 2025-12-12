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
func (f AlienVault) QuerySubdomain(ctx context.Context, session *sources.Session, domain string) ([]string, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}

	req := &sources.Req{
		Schema:   "https",
		Endpoint: "otx.alienvault.com",
		Path:     fmt.Sprintf("/api/v1/indicators/domain/%s/passive_dns", domain),
		Method:   "GET",
		Header:   map[string]string{"X-OTX-API-KEY": *apikey},
	}

	request, err := req.Request()
	if err != nil {
		return nil, err
	}

	resp, err := session.Do(request, f.Name())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	type avResponse struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	var avResp avResponse
	if err := json.NewDecoder(resp.Body).Decode(&avResp); err != nil {
		return nil, err
	}

	res := make(map[string]struct{})
	for _, r := range avResp.PassiveDNS {
		sub := r.Hostname
		if strings.HasSuffix(sub, "."+domain) {
			res[sub] = struct{}{}
		}
	}

	result := make([]string, 0, len(res))
	for k := range res {
		result = append(result, k)
	}
	return result, nil
}

// QueryAsset 不支持资产测绘
func (f AlienVault) QueryAsset(ctx context.Context, session *sources.Session, query interface{}) (chan sources.Result, error) {
	return nil, nil
}

func init() {
	registerPlugin("alienvault", AlienVault{})
}
