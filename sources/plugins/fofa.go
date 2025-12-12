package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/404tk/cmap/options"
	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

const (
	FofaFields = "ip,port,base_protocol,protocol,domain,host,title,product,lastupdatetime"
	FofaSize   = 1000
)

type Fofa struct {
	Email   string
	Key     string
	session *sources.Session
	results chan sources.Result
}

func (f Fofa) Name() string {
	return "fofa"
}

func (f Fofa) QueryAsset(ctx context.Context, session *sources.Session, query interface{}) (chan sources.Result, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}
	parts := strings.Split(*apikey, ":")
	if len(parts) > 1 {
		f.Email = parts[0]
		f.Key = parts[1]
	} else {
		return nil, errors.New("Fofa key parse failed")
	}
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
			f.queryIcon(ctx, q.Mmh3)
		}
		for _, q := range k.DSL {
			str := q.Expr
			for i, g := range q.Groups {
				dsl := f.parseDSL(g.Key, g.Symbol, g.Value)
				if dsl == "" {
					break
				}
				str = strings.Replace(str, fmt.Sprintf("[%d]", i), dsl, 1)
			}
			f.search(ctx, str, q.Raw)
		}
	}()
	return f.results, nil
}

func (f Fofa) queryIP(ctx context.Context, ip string) {
	if len(ip) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("ip", "==", ip), ip)
}

func (f Fofa) queryDomain(ctx context.Context, domain string) {
	if len(domain) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("domain", "=", domain), domain)
}

func (f Fofa) queryIcon(ctx context.Context, hash string) {
	if len(hash) == 0 {
		return
	}
	f.search(ctx, f.parseDSL("icon.mmh3", "==", hash), hash)
}

func (f Fofa) parseDSL(k, s, v string) string {
	switch k {
	case "ip":
		return fmt.Sprintf(`ip%s"%s"`, s, v)
	case "domain":
		return fmt.Sprintf(`domain%s"%s"`, s, v)
	case "icon.mmh3":
		return fmt.Sprintf(`icon_hash%s"%s"`, s, v)
	case "cert":
		return fmt.Sprintf(`cert%s"%s"`, s, v)
	case "title":
		return fmt.Sprintf(`title%s"%s"`, s, v)
	case "body":
		return fmt.Sprintf(`body%s"%s"`, s, v)
	default:
		return ""
	}
}

// FofaResponse contains the fofa response
type FofaResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Mode    string     `json:"mode"`
	Page    int        `json:"page"`
	Query   string     `json:"query"`
	Results [][]string `json:"results"`
	Size    int        `json:"size"`
}

func (f Fofa) search(ctx context.Context, query, prompt string) {
	page := 1
	for {
		req := &sources.Req{
			Schema:   "https",
			Endpoint: "fofa.info",
			Path:     "/api/v1/search/all",
			Method:   "GET",
			Header:   map[string]string{"Accept": "application/json"},
		}
		qbase64 := base64.StdEncoding.EncodeToString([]byte(query))
		req.Query = fmt.Sprintf("mail=%s&key=%s&qbase64=%s&fields=%s&page=%d&size=%d",
			f.Email, f.Key, qbase64, FofaFields, page, FofaSize)
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

		fofaResponse := &FofaResponse{}
		if err := json.NewDecoder(resp.Body).Decode(fofaResponse); err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}
		if fofaResponse.Error {
			f.results <- sources.Result{Source: f.Name(), Error: errors.New(fofaResponse.ErrMsg)}
			return
		}

		for _, fofaResult := range fofaResponse.Results {
			result := sources.Result{Source: f.Name(), Prompt: prompt}
			result.IP = fofaResult[0]
			result.Port = fmt.Sprintf("%s/%s", fofaResult[1], fofaResult[2])
			result.Protocol = fofaResult[3]
			if len(fofaResult[4]) > 0 {
				result.Host = append(result.Host, fofaResult[4])
			}
			if strings.HasPrefix(fofaResult[3], "http") {
				result.Url = fofaResult[5]
				if !strings.HasPrefix(result.Url, "http") {
					result.Url = "http://" + fofaResult[5]
				}
				result.Title = truncateString(fofaResult[6], 100)
			}
			result.Fingerprint = fofaResult[7]
			result.LastUpdate = fofaResult[8]
			f.results <- result
		}

		if fofaResponse.Size < FofaSize || len(fofaResponse.Results) == 0 {
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

func init() {
	registerPlugin("fofa", Fofa{})
}

// QuerySubdomain 子域名收集
func (f Fofa) QuerySubdomain(ctx context.Context, session *sources.Session, domain string) (chan string, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}
	parts := strings.Split(*apikey, ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid %s key format", f.Name())
	}
	email, key := parts[0], parts[1]

	results := make(chan string)
	go func() {
		defer close(results)

		query := fmt.Sprintf(`domain="%s"`, domain)
		qbase64 := base64.StdEncoding.EncodeToString([]byte(query))
		seen := make(map[string]struct{})
		page := 1

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			req := &sources.Req{
				Schema:   "https",
				Endpoint: "fofa.info",
				Path:     "/api/v1/search/all",
				Method:   "GET",
				Header:   map[string]string{},
				Query: fmt.Sprintf("email=%s&key=%s&page=%d&size=%d&qbase64=%s&fields=host",
					email, key, page, FofaSize, qbase64),
			}
			request, err := req.Request()
			if err != nil {
				return
			}
			resp, err := session.Do(request, f.Name())
			if err != nil {
				return
			}

			// 单字段查询返回 []string 而非 [][]string
			type fofaSingleFieldResponse struct {
				Error   bool     `json:"error"`
				ErrMsg  string   `json:"errmsg"`
				Size    int      `json:"size"`
				Results []string `json:"results"`
			}
			fofaResponse := &fofaSingleFieldResponse{}
			if err := json.NewDecoder(resp.Body).Decode(fofaResponse); err != nil {
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			if fofaResponse.Error {
				return
			}

			for _, sub := range fofaResponse.Results {
				if strings.HasPrefix(sub, "https://") || strings.HasPrefix(sub, "http://") {
					sub = strings.Split(sub, "://")[1]
				}
				sub = strings.Split(sub, ":")[0]
				if strings.HasSuffix(sub, "."+domain) {
					if _, ok := seen[sub]; !ok {
						seen[sub] = struct{}{}
						results <- sub
					}
				}
			}

			// 判断是否还有更多数据
			if fofaResponse.Size < FofaSize || len(fofaResponse.Results) == 0 {
				return
			}
			page++
		}
	}()

	return results, nil
}

// VerifyKeys 验证 FOFA API 密钥
func (f Fofa) VerifyKeys(session *sources.Session) []config.KeyStatus {
	keys := config.GetKeys(f.Name())
	if len(keys) == 0 {
		return nil
	}

	results := make([]config.KeyStatus, 0, len(keys))
	for _, key := range keys {
		status := config.KeyStatus{Key: maskKey(key)}

		parts := strings.Split(key, ":")
		if len(parts) < 2 {
			status.Error = fmt.Errorf("invalid key format")
			results = append(results, status)
			continue
		}

		req := &sources.Req{
			Schema:   "https",
			Endpoint: "fofa.info",
			Path:     "/api/v1/info/my",
			Method:   "GET",
			Header:   map[string]string{},
			Query:    fmt.Sprintf("key=%s", parts[1]),
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

		type fofaUserInfo struct {
			Error           bool   `json:"error"`
			Email           string `json:"email"`
			Username        string `json:"username"`
			Category        string `json:"category"`
			FCoin           int    `json:"fcoin"`
			FofaPoint       int    `json:"fofa_point"`
			RemainFreePoint int    `json:"remain_free_point"`
			RemainAPIQuery  int    `json:"remain_api_query"`
			RemainAPIData   int    `json:"remain_api_data"`
			Isvip           bool   `json:"isvip"`
			VipLevel        int    `json:"vip_level"`
			IsVerified      bool   `json:"is_verified"`
			Avatar          string `json:"avatar"`
			Message         string `json:"message"`
			FofacliVer      string `json:"fofacli_ver"`
			FofaServer      bool   `json:"fofa_server"`
		}
		var info fofaUserInfo
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			resp.Body.Close()
			status.Error = err
			results = append(results, status)
			continue
		}
		resp.Body.Close()

		if info.Error {
			status.Error = fmt.Errorf("%s", info.Message)
			results = append(results, status)
			continue
		}

		status.Valid = true
		status.Credits = int64(info.RemainAPIData)
		status.Info = fmt.Sprintf("VIP%d", info.VipLevel)
		results = append(results, status)
	}
	return results
}
