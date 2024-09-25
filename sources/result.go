package sources

import (
	"encoding/json"
	"net"
	"strings"
)

type Result struct {
	IP          string   `json:"ip" excel:"name:IP;"`
	Port        string   `json:"port" excel:"name:端口;"`
	Protocol    string   `json:"protocol" excel:"name:服务;"`
	Host        []string `json:"host"`
	Url         string   `json:"url" excel:"name:URL;"`
	Title       string   `json:"title" excel:"name:网站标题;"`
	Fingerprint string   `json:"fingerprint" excel:"name:指纹;"`
	Source      string   `json:"source" excel:"name:来源;"`
	Prompt      string   `json:"prompt" excel:"name:查询语句;"`
	LastUpdate  string   `json:"lastupdate" excel:"name:更新时间;"`
	Timestamp   int64    `json:"timestamp"`
	Error       error    `json:"-"`
}

func (r *Result) IpPort() string {
	return net.JoinHostPort(r.IP, strings.Split(r.Port, "/")[0])
}

func (r *Result) PrettyPrint() string {
	msg := r.IpPort() + "\t" + r.Protocol
	if len(r.Fingerprint) > 0 {
		msg += "\t" + r.Fingerprint
	}
	return msg
}

func (r *Result) JSON() string {
	data, _ := json.Marshal(r)
	return string(data)
}

type ResultSet []Result

func NewResultSet(a ...Result) *ResultSet {
	s := &ResultSet{}
	s.Add(a...)
	return s
}

func (this *ResultSet) Add(n ...Result) {
	for _, r := range n {
		*this = append(*this, r)
	}
}

func (this *ResultSet) AsArray() []Result {
	a := []Result{}
	for _, n := range *this {
		a = append(a, n)
	}
	return a
}

type IpDomain struct {
	IP     string `excel:"name:IP;"`
	Domain string `excel:"name:域名;"`
}

func IpDomainArray(ip string, hosts []string) []IpDomain {
	res := []IpDomain{}
	for _, host := range hosts {
		res = append(res, IpDomain{IP: ip, Domain: host})
	}
	return res
}
