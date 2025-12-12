package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

type CrtSh struct{}

func (f CrtSh) Name() string {
	return "crtsh"
}

// QuerySubdomain 子域名收集（无需凭据）
func (f CrtSh) QuerySubdomain(ctx context.Context, session *sources.Session, domain string) ([]string, error) {
	req := &sources.Req{
		Schema:   "https",
		Endpoint: "crt.sh",
		Path:     "/",
		Method:   "GET",
		Header:   map[string]string{},
		Query:    fmt.Sprintf("q=%%.%s&output=json", domain),
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

	type crtResult struct {
		NameValue string `json:"name_value"`
	}
	var results []crtResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	res := make(map[string]struct{})
	for _, r := range results {
		items := strings.Split(r.NameValue, "\n")
		for _, sub := range items {
			if strings.HasSuffix(sub, "."+domain) &&
				!strings.Contains(sub, "*") {
				res[sub] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(res))
	for k := range res {
		result = append(result, k)
	}
	return result, nil
}

// QueryAsset 不支持资产测绘
func (f CrtSh) QueryAsset(ctx context.Context, session *sources.Session, query interface{}) (chan sources.Result, error) {
	return nil, nil
}

// VerifyKeys 无需凭据
func (f CrtSh) VerifyKeys(session *sources.Session) []config.KeyStatus {
	return nil
}

func init() {
	registerPlugin("crtsh", CrtSh{})
}
