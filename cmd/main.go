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
	ipMap := make(map[string]interface{})
	result := func(result sources.Result) {
		if result.Error != nil {
			fmt.Printf("[%s] %v\n", result.Source, result.Error)
		} else {
			// 基于IP、端口、请求地址生成唯一hash进行去重
			index := generateHash(fmt.Sprintf("%s_%s_%s", result.IP, result.Port, result.Url))
			if _, ok := hashMap[index]; ok {
				hashMap[index] += 1
			} else {
				hashMap[index] = 0
				if v, ok := ipMap[result.IP]; ok {
					ipMap[result.IP] = append(v.([]sources.Result), result)
				} else {
					ipMap[result.IP] = []sources.Result{result}
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

func excelExport(data map[string]interface{}) {
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

	e.F.SetSheetName("Sheet1", "IP视角")

	err := e.ExportExcel("IP视角", "IP视角", data, nil)
	if err != nil {
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
