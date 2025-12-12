package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/404tk/cmap/options"
	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

const (
	HunterSize = 100
)

type Hunter struct {
	apikey  string
	session *sources.Session
	results chan sources.Result
}

func (f Hunter) Name() string {
	return "hunter"
}

func (f Hunter) QueryAsset(ctx context.Context, session *sources.Session, query interface{}) (chan sources.Result, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}
	f.apikey = *apikey
	f.session = session
	f.results = make(chan sources.Result)

	k := query.(options.Keyword)
	go func() {
		defer close(f.results)

		for _, ip := range k.IP {
			f.queryIP(ctx, ip)
		}
		for _, domain := range k.Domain {
			f.queryDomain(ctx, domain)
		}
		for _, q := range k.Icons {
			f.queryIcon(ctx, q.Md5)
		}
		for _, q := range k.DSL {
			str := q.Expr
			for i, g := range q.Groups {
				dsl := f.parseDSL(g.Key, g.Symbol, g.Value)
				if dsl == "" {
					goto next
				}
				str = strings.Replace(str, fmt.Sprintf("[%d]", i), dsl, 1)
			}
			f.search(ctx, str, q.Raw)
		next:
		}
	}()

	return f.results, nil
}

func (f Hunter) queryIP(ctx context.Context, ip string) {
	if len(ip) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("ip", "==", ip), ip)
}

func (f Hunter) queryDomain(ctx context.Context, domain string) {
	if len(domain) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("domain", "=", domain), domain)
}

func (f Hunter) queryIcon(ctx context.Context, hash string) {
	if len(hash) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("icon.md5", "==", hash), hash)
}

func (f Hunter) parseDSL(k, s, v string) string {
	switch k {
	case "ip":
		return fmt.Sprintf(`ip%s"%s"`, s, v)
	case "domain":
		return fmt.Sprintf(`domain.suffix%s"%s"`, s, v)
	case "icon.md5":
		return fmt.Sprintf(`web.icon%s"%s"`, s, v)
	case "cert":
		return fmt.Sprintf(`cert%s"%s"`, s, v)
	case "title":
		return fmt.Sprintf(`web.title%s"%s"`, s, v)
	case "body":
		return fmt.Sprintf(`web.body%s"%s"`, s, v)
	default:
		return ""
	}
}

type HunterResponse struct {
	Code int `json:"code"`
	Data struct {
		AccountType string `json:"account_type"`
		Total       int    `json:"total"`
		Time        int    `json:"time"`
		Arr         []struct {
			IP           string `json:"ip"`
			Port         int    `json:"port"`
			Domain       string `json:"domain"`
			BaseProtocol string `json:"base_protocol"`
			Protocol     string `json:"protocol"`
			UpdatedAt    string `json:"updated_at"`
			Url          string `json:"url"`
			WebTitle     string `json:"web_title"`
		} `json:"arr"`
		ConsumeQuota string `json:"consume_quota"`
		RestQuota    string `json:"rest_quota"`
	} `json:"data"`
	Msg string `json:"message"`
}

func (f Hunter) search(ctx context.Context, query, prompt string) {
	page := 1
	for {
		base64Query := base64.URLEncoding.EncodeToString([]byte(query))
		req := &sources.Req{
			Schema:   "https",
			Endpoint: "hunter.qianxin.com",
			Path:     "/openApi/search",
			Method:   "GET",
			Header:   map[string]string{"Accept": "application/json"},
			Query: fmt.Sprintf("api-key=%s&search=%s&page=%d&page_size=%d",
				f.apikey, base64Query, page, HunterSize),
		}

		request, err := req.Request()
		if err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}
		resp, err := f.session.Do(request, f.Name())
		if err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}

		hunterResponse := &HunterResponse{}
		if err := json.NewDecoder(resp.Body).Decode(hunterResponse); err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}
		if hunterResponse.Code != 200 {
			f.results <- sources.Result{Source: f.Name(), Error: errors.New(hunterResponse.Msg)}
			return
		}

		for _, res := range hunterResponse.Data.Arr {
			result := sources.Result{Source: f.Name(), Prompt: prompt}
			result.IP = res.IP
			result.Port = fmt.Sprintf("%d/%s", res.Port, res.BaseProtocol)
			result.Protocol = res.Protocol
			if len(res.Domain) > 0 {
				result.Host = append(result.Host, res.Domain)
			}
			result.Url = res.Url
			result.Title = res.WebTitle
			parsedTime, err := time.Parse(time.DateOnly, res.UpdatedAt)
			if err == nil {
				result.LastUpdate = parsedTime.Format(time.DateTime)
			}
			f.results <- result
		}

		if len(hunterResponse.Data.Arr) < HunterSize || hunterResponse.Data.Total == 0 {
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
			page++
		}
	}
}

// QuerySubdomain 不支持子域名收集
func (f Hunter) QuerySubdomain(ctx context.Context, session *sources.Session, domain string) ([]string, error) {
	return nil, nil
}

// VerifyKeys 验证 Hunter API 密钥
func (f Hunter) VerifyKeys(session *sources.Session) []config.KeyStatus {
	keys := config.GetKeys(f.Name())
	if len(keys) == 0 {
		return nil
	}

	results := make([]config.KeyStatus, 0, len(keys))
	for _, key := range keys {
		status := config.KeyStatus{Key: maskKey(key)}

		req := &sources.Req{
			Schema:   "https",
			Endpoint: "hunter.qianxin.com",
			Path:     "/openApi/userInfo",
			Method:   "GET",
			Header:   map[string]string{},
			Query:    fmt.Sprintf("api-key=%s", key),
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

		type hunterUserInfo struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Type             string `json:"type"`
				RestEquityPoint  int64  `json:"rest_equity_point"`
				RestFreePoint    int64  `json:"rest_free_point"`
				RestExportQuota  int64  `json:"rest_export_quota"`
				DayFreePoint     int64  `json:"day_free_point"`
				DayExportQuota   int64  `json:"day_export_quota"`
				OnceExportQuota  int64  `json:"once_export_quota"`
				PersonalInfo     struct {
					Username string `json:"username"`
					Phone    string `json:"phone"`
					IsCharge bool   `json:"is_charge"`
				} `json:"personal_info"`
			} `json:"data"`
		}
		var info hunterUserInfo
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			resp.Body.Close()
			status.Error = err
			results = append(results, status)
			continue
		}
		resp.Body.Close()

		if info.Code != 200 {
			status.Error = fmt.Errorf("%s", info.Message)
			results = append(results, status)
			continue
		}

		status.Valid = true
		status.Credits = info.Data.RestEquityPoint
		status.Info = fmt.Sprintf("%s, 当日免费积分: %d/%d",
			info.Data.Type, info.Data.RestFreePoint, info.Data.DayFreePoint)
		results = append(results, status)
	}
	return results
}

func init() {
	registerPlugin("hunter", Hunter{})
}
