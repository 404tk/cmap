package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/404tk/cmap"
	"github.com/404tk/cmap/cmd/excel"
	"github.com/404tk/cmap/options"
	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
	"github.com/404tk/cmap/sources/plugins"
	"github.com/404tk/cmap/utils"
)

var (
	agent      string
	ip         string
	domain     string
	md5_str    string
	mmh3_str   string
	cert       string
	configPath string
	output     string
)

func init() {
	flag.StringVar(&agent, "agent", "fofa,quake,hunter,shodan", "Agent")
	flag.StringVar(&ip, "ip", "", "IP")
	flag.StringVar(&domain, "domain", "", "Domain")
	flag.StringVar(&md5_str, "md5", "", "Favicon md5")
	flag.StringVar(&mmh3_str, "mmh3", "", "Favicon mmh3")
	flag.StringVar(&cert, "cert", "", "Certificate")
	flag.StringVar(&configPath, "config", "config.yaml", "config file path")
	flag.StringVar(&output, "oX", "", "output filename")
	flag.Parse()

	if len(output) == 0 {
		output = fmt.Sprintf("result_%d.xlsx", time.Now().Unix())
	}
}

func main() {
	config.InitConfig(configPath)
	opts := &options.Options{
		Agents: strings.Split(agent, ","),
		Query: plugins.Keyword{
			IP:     []string{ip},
			Domain: []string{domain},
			Icon: []struct {
				Md5  string
				Mmh3 string
			}{{md5_str, mmh3_str}},
			Cert: []string{cert},
		},
		Timeout: 20,
	}

	u, err := cmap.New(opts)
	if err != nil {
		panic(err)
	}

	hashMap := make(map[string]int)
	ipMap := make(map[string]ipDetail)
	result := func(result sources.Result) {
		if result.Error != nil {
			fmt.Printf("[%s] %v\n", result.Source, result.Error)
		} else {
			// 基于IP、端口生成唯一hash进行去重
			index := generateHash(fmt.Sprintf("%s_%s", result.IP, result.Port))
			if _, ok := hashMap[index]; ok {
				hashMap[index] += 1
			} else {
				hashMap[index] = 1
				if v, ok := ipMap[result.IP]; ok {
					v.Ports.Add(result)
					v.Hosts.AddAll(result.Host)
				} else {
					ipMap[result.IP] = ipDetail{
						Ports: sources.NewResultSet(result),
						Hosts: utils.NewStringSetByArray(result.Host),
					}
				}
			}
			fmt.Printf("[%s] %s %s\n", result.Source, result.PrettyPrint(), result.Title)
		}
	}

	// Execute executes and returns a channel with all results
	// ch , err := u.Execute(context.Background())

	// Execute with Callback calls u.Execute() internally and abstracts channel handling logic
	if err := u.ExecuteWithCallback(context.TODO(), result); err != nil {
		panic(err)
	}
	excelExport(ipMap)
}

type ipDetail struct {
	Ports *sources.ResultSet
	Hosts utils.StringSet
}

func excelExport(data map[string]ipDetail) {
	if !strings.HasSuffix(output, ".xlsx") {
		fmt.Println("导出文件仅支持.xlsx格式！")
		return
	}
	e := excel.ExcelInit()
	defer func() {
		if err := e.F.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	portMap := make(map[string]interface{})
	hostMap := make(map[string]interface{})
	for ip, d := range data {
		portMap[ip] = d.Ports.AsArray()
		hostMap[ip] = sources.IpDomainArray(ip, d.Hosts.AsArray())
	}

	e.F.SetSheetName("Sheet1", "端口服务")
	if err := e.ExportExcel("端口服务", "端口服务", portMap, nil); err != nil {
		return
	}

	e.F.NewSheet("关联域名")
	if err := e.ExportExcel("关联域名", "关联域名", hostMap, nil); err != nil {
		return
	}

	if err := e.F.SaveAs(output); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("结果已导出至", output)
}

func generateHash(s string) string {
	hasher := md5.New()
	hasher.Write([]byte(s))
	return hex.EncodeToString(hasher.Sum(nil))
}
