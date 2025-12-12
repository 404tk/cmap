package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/404tk/cmap/options"
	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

const (
	ZoomeyeSize   = 30
	ZoomeyeFields = "ip,port,domain,url,hostname,service,title,product,update_time"
)

type Zoomeye struct {
	apikey  string
	session *sources.Session
	results chan sources.Result
}

func (f Zoomeye) Name() string {
	return "zoomeye"
}

func (f Zoomeye) QueryAsset(ctx context.Context, session *sources.Session, query interface{}) (chan sources.Result, error) {
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
			if q.Mmh3 != "" {
				f.queryIcon(ctx, q.Mmh3)
			}
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

func (f Zoomeye) queryIP(ctx context.Context, ip string) {
	if len(ip) == 0 {
		return
	}
	query := fmt.Sprintf(`ip="%s"`, ip)
	f.search(ctx, query, ip)
}

func (f Zoomeye) queryDomain(ctx context.Context, domain string) {
	if len(domain) == 0 {
		return
	}
	query := fmt.Sprintf(`domain="%s"`, domain)
	f.search(ctx, query, domain)
}

func (f Zoomeye) queryIcon(ctx context.Context, hash string) {
	if len(hash) == 0 {
		return
	}
	query := fmt.Sprintf(`iconhash="%s"`, hash)
	f.search(ctx, query, hash)
}

func (f Zoomeye) parseDSL(key, s, v string) string {
	switch key {
	case "ip":
		return fmt.Sprintf(`ip%s"%s"`, s, v)
	case "domain":
		return fmt.Sprintf(`site%s"%s"`, s, v)
	case "title":
		return fmt.Sprintf(`title%s"%s"`, s, v)
	case "body":
		return fmt.Sprintf(`http.body%s"%s"`, s, v)
	case "icon.mmh3", "icon.md5":
		return fmt.Sprintf(`iconhash%s"%s"`, s, v)
	case "cert":
		return fmt.Sprintf(`ssl%s"%s"`, s, v)
	default:
		return ""
	}
}

type ZoomEyeRequest struct {
	QBase64  string `json:"qbase64"`
	Page     int    `json:"page"`
	PageSize int    `json:"pagesize"`
	Fields   string `json:"fields"`
}

type ZoomEyeResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Total   int    `json:"total"`
	Query   string `json:"query"`
	Data    []struct {
		Url                 string   `json:"url"`
		SslJarm             string   `json:"ssl.jarm"`
		SslJa3S             string   `json:"ssl.ja3s"`
		IconhashMd5         string   `json:"iconhash_md5"`
		RobotsMd5           string   `json:"robots_md5"`
		SecurityMd5         string   `json:"security_md5"`
		Ip                  string   `json:"ip"`
		Domain              string   `json:"domain"`
		Hostname            string   `json:"hostname"`
		Os                  string   `json:"os"`
		Port                int      `json:"port"`
		Service             string   `json:"service"`
		Title               []string `json:"title"`
		Version             string   `json:"version"`
		Device              string   `json:"device"`
		Rdns                string   `json:"rdns"`
		Product             string   `json:"product"`
		Header              string   `json:"header"`
		HeaderHash          string   `json:"header_hash"`
		Body                string   `json:"body"`
		BodyHash            string   `json:"body_hash"`
		Banner              string   `json:"banner"`
		UpdateTime          string   `json:"update_time"`
		HeaderServerName    string   `json:"header.server.name"`
		HeaderServerVersion string   `json:"header.server.version"`
		ContinentName       string   `json:"continent.name"`
		CountryName         string   `json:"country.name"`
		ProvinceName        string   `json:"province.name"`
		CityName            string   `json:"city.name"`
		Lon                 string   `json:"lon"`
		Lat                 string   `json:"lat"`
		IspName             string   `json:"isp.name"`
		OrganizationName    string   `json:"organization.name"`
		Zipcode             string   `json:"zipcode"`
		Idc                 int      `json:"idc"`
		Honeypot            int      `json:"honeypot"`
		Asn                 string   `json:"asn"`
		Protocol            string   `json:"protocol"`
		Ssl                 string   `json:"ssl"`
		PrimaryIndustry     string   `json:"primary_industry"`
		SubIndustry         string   `json:"sub_industry"`
		Rank                int      `json:"rank"`
	} `json:"data"`
}

func (f Zoomeye) search(ctx context.Context, query, prompt string) {
	page := 1
	var numberOfResults int

	// Base64 编码查询字符串
	qbase64 := base64.StdEncoding.EncodeToString([]byte(query))

	for {
		reqBody := ZoomEyeRequest{
			QBase64:  qbase64,
			Page:     page,
			PageSize: ZoomeyeSize,
		}

		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}

		req := &sources.Req{
			Schema:   "https",
			Endpoint: "api.zoomeye.org",
			Path:     "/v2/search",
			Method:   "POST",
			Header: map[string]string{
				"API-KEY":      f.apikey,
				"Content-Type": "application/json",
			},
			Body: string(bodyBytes),
		}

		request, err := req.Request()
		if err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}

		resp, err := f.session.Do(request, f.Name())
		if err != nil {
			// 如果是 402 错误，尝试读取详细错误信息
			if resp != nil {
				var errResp ZoomEyeResponse
				if json.NewDecoder(resp.Body).Decode(&errResp) == nil {
					resp.Body.Close()
					f.results <- sources.Result{Source: f.Name(), Error: fmt.Errorf("code: %d,err: %s", errResp.Code, errResp.Message)}
					return
				}
				resp.Body.Close()
			}
			f.results <- sources.Result{Source: f.Name(), Error: err}
			return
		}

		zoomeyeResponse := &ZoomEyeResponse{}
		if err := json.NewDecoder(resp.Body).Decode(zoomeyeResponse); err != nil {
			f.results <- sources.Result{Source: f.Name(), Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		// 检查响应状态
		if zoomeyeResponse.Code != 60000 {
			f.results <- sources.Result{Source: f.Name(), Error: fmt.Errorf("API error: %s", zoomeyeResponse.Message)}
			return
		}

		numberOfResults += len(zoomeyeResponse.Data)

		for _, res := range zoomeyeResponse.Data {
			result := sources.Result{Source: f.Name(), Prompt: prompt}

			// 提取基本信息
			result.IP = res.Ip
			result.Port = fmt.Sprint(res.Port)
			result.Protocol = res.Service

			// 提取域名和主机名
			result.Host = append(result.Host, res.Domain)
			result.Host = append(result.Host, res.Hostname)

			// 提取标题
			if len(res.Title) > 0 {
				result.Title = res.Title[0]
			}

			// 提取产品指纹
			result.Fingerprint = res.Product

			// 提取更新时间
			parsedTime, err := time.Parse(time.RFC3339[:19], res.UpdateTime)
			if err == nil {
				result.LastUpdate = parsedTime.Format(time.DateTime)
			}

			// 构建 URL（优先使用 API 返回的 URL）
			if res.Url != "" {
				result.Url = res.Url
			} else if result.IP != "" && result.Port != "" {
				if result.Protocol == "https" || result.Protocol == "http" {
					result.Url = fmt.Sprintf("%s://%s:%s", result.Protocol, result.IP, result.Port)
				}
			}
			f.results <- result
		}

		// 检查是否还有更多结果
		if len(zoomeyeResponse.Data) < ZoomeyeSize || numberOfResults >= zoomeyeResponse.Total {
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
	registerPlugin("zoomeye", Zoomeye{})
}

// QuerySubdomain 子域名收集（使用 domain/search 接口）
func (f Zoomeye) QuerySubdomain(ctx context.Context, session *sources.Session, domain string) ([]string, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}

	req := &sources.Req{
		Schema:   "https",
		Endpoint: "api.zoomeye.org",
		Path:     "/domain/search",
		Method:   "GET",
		Header:   map[string]string{"API-KEY": *apikey},
	}

	page := 1
	var numberOfResults, total int
	res := make(map[string]struct{})
	var lastErr error

	for {
		select {
		case <-ctx.Done():
			goto done
		default:
		}
		req.Query = fmt.Sprintf("q=%s&type=1&page=%d", domain, page)
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

		type zoomeyeDomain struct {
			Total int `json:"total"`
			List  []struct {
				Name string `json:"name"`
			} `json:"list"`
		}
		var dnsResp zoomeyeDomain
		if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
			resp.Body.Close()
			lastErr = err
			break
		}
		resp.Body.Close()

		if total == 0 {
			total = dnsResp.Total
		}
		numberOfResults += len(dnsResp.List)

		for _, r := range dnsResp.List {
			sub := r.Name
			if strings.HasSuffix(sub, "."+domain) {
				res[sub] = struct{}{}
			}
		}

		if len(dnsResp.List) < 30 || numberOfResults >= total {
			break
		}
		page++
	}

done:
	result := make([]string, 0, len(res))
	for k := range res {
		result = append(result, k)
	}
	return result, lastErr
}

// VerifyKeys 验证 Zoomeye API 密钥
func (f Zoomeye) VerifyKeys(session *sources.Session) []config.KeyStatus {
	keys := config.GetKeys(f.Name())
	if len(keys) == 0 {
		return nil
	}

	results := make([]config.KeyStatus, 0, len(keys))
	for i, key := range keys {
		// Zoomeye 限速 1 req/s
		if i > 0 {
			time.Sleep(time.Second)
		}
		status := config.KeyStatus{Key: maskKey(key)}

		req := &sources.Req{
			Schema:   "https",
			Endpoint: "api.zoomeye.org",
			Path:     "/resources-info",
			Method:   "GET",
			Header:   map[string]string{"API-KEY": key},
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

		type zoomeyeResourceInfo struct {
			QuotaInfo struct {
				RemainTotalQuota int64 `json:"remain_total_quota"`
			} `json:"quota_info"`
		}
		var info zoomeyeResourceInfo
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			resp.Body.Close()
			status.Error = err
			results = append(results, status)
			continue
		}
		resp.Body.Close()

		status.Valid = true
		status.Credits = info.QuotaInfo.RemainTotalQuota
		results = append(results, status)
	}
	return results
}
