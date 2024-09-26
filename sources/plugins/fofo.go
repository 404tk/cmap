package plugins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

const (
	FofaFields = "ip,port,base_protocol,protocol,domain,host,title,product,lastupdatetime"
	FofaSize   = 10000
)

type Fofa struct {
	auth    config.FofaAuth
	session *sources.Session
	results chan sources.Result
}

func (f Fofa) Name() string {
	return "fofa"
}

func (f Fofa) Query(session *sources.Session, query interface{}) (chan sources.Result, error) {
	apikey := config.RandomKey(f.Name())
	if apikey == nil {
		return nil, fmt.Errorf("empty %s keys", f.Name())
	}
	f.auth = apikey.(config.FofaAuth)
	f.session = session
	f.results = make(chan sources.Result)

	// 查询总时长限制10分钟
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	k := query.(Keyword)
	go func() {
		defer close(f.results)

		for _, ip := range k.IP {
			f.QueryIP(ctx, ip)
		}
		for _, domain := range k.Domain {
			f.QueryDomain(ctx, domain)
		}
		for _, q := range k.Icon {
			f.QueryIcon(ctx, q.Mmh3)
		}
		for _, cert := range k.Cert {
			f.QueryCert(ctx, cert)
		}
	}()

	return f.results, nil
}

func (f Fofa) QueryIP(ctx context.Context, ip string) {
	if len(ip) == 0 {
		return
	}
	query := fmt.Sprintf(`ip="%s"`, ip)
	f.search(ctx, query)
}

func (f Fofa) QueryDomain(ctx context.Context, domain string) {
	if len(domain) == 0 {
		return
	}
	query := fmt.Sprintf(`domain="%s"`, domain)
	f.search(ctx, query)
}

func (f Fofa) QueryIcon(ctx context.Context, hash string) {
	if len(hash) == 0 {
		return
	}
	query := fmt.Sprintf(`icon_hash="%s"`, hash)
	f.search(ctx, query)
}

func (f Fofa) QueryCert(ctx context.Context, keyword string) {
	if len(keyword) == 0 {
		return
	}
	query := fmt.Sprintf(`cert="%s"`, keyword)
	f.search(ctx, query)
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

func (f Fofa) search(ctx context.Context, query string) {
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
			f.auth.Email, f.auth.Key, qbase64, FofaFields, page, FofaSize)
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
			f.results <- sources.Result{Source: f.Name(), Error: fmt.Errorf(fofaResponse.ErrMsg)}
			return
		}

		for _, fofaResult := range fofaResponse.Results {
			result := sources.Result{Source: f.Name()}
			result.IP = fofaResult[0]
			result.Port = fmt.Sprintf("%s/%s", fofaResult[1], fofaResult[2])
			result.Protocol = fofaResult[3]
			if len(fofaResult[4]) > 0 {
				result.Host = append(result.Host, fofaResult[4])
			}
			if strings.HasPrefix(fofaResult[3], "http") {
				result.Url = fofaResult[5]
				result.Title = fofaResult[6]
			}
			result.Fingerprint = fofaResult[7]
			result.LastUpdate = fofaResult[8]
			result.Prompt = query
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
