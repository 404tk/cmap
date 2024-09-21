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
	keyword    plugins.Keyword
	configPath string
	output     string
)

func init() {
	flag.StringVar(&agent, "agent", "fofa,quake,hunter,shodan", "Agent")
	flag.StringVar(&keyword.IP, "ip", "", "IP")
	flag.StringVar(&keyword.Domain, "domain", "", "Domain")
	flag.StringVar(&keyword.Icon.Md5, "md5", "", "Favicon md5")
	flag.StringVar(&keyword.Icon.Mmh3, "mmh3", "", "Favicon mmh3")
	flag.StringVar(&keyword.Cert, "cert", "", "Certificate")
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
		Agents:  strings.Split(agent, ","),
		Query:   keyword,
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

	e.F.SetSheetName("Sheet1", "结果导出")

	err := e.ExportExcel("结果导出", "结果导出", data, nil)
	if err != nil {
		return
	}

	if err := e.F.SaveAs(output); err != nil {
		fmt.Println(err)
		return
	}
}

func generateHash(s string) string {
	hasher := md5.New()
	hasher.Write([]byte(s))
	return hex.EncodeToString(hasher.Sum(nil))
}
