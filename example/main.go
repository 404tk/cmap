package main

import (
	"context"
	"fmt"
	"time"

	"github.com/404tk/cmap"
	"github.com/404tk/cmap/options"
	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
)

func main() {
	// 设置凭据
	config.SetKeys(config.PlatformFofa, []string{"user@gmail.com:fofa_key"})
	config.SetKeys(config.PlatformQuake, []string{"quake_token"})
	config.SetKeys(config.PlatformShodan, []string{"shodan_key"})
	config.SetKeys(config.PlatformHunter, []string{"hunter_key"})
	config.SetKeys(config.PlatformVirusTotal, []string{"vt_key"})

	// 示例1：子域名收集
	subdomainExample()

	// 示例2：资产测绘
	assetExample()
}

// subdomainExample 子域名收集示例
func subdomainExample() {
	fmt.Println("=== 子域名收集 ===")
	opts := &options.Options{
		Agents: []string{"fofa", "shodan", "crtsh", "virustotal"},
		Query: options.Keyword{
			Domain: []string{"example.com"},
		},
		Timeout: 20, // 单个请求超时
	}

	svc, err := cmap.New(opts)
	if err != nil {
		panic(err)
	}

	// 整体查询超时 5 分钟
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	subs, err := svc.ExecuteSubdomainUnique(ctx)
	if err != nil {
		panic(err)
	}

	fmt.Printf("共发现 %d 个子域名:\n", len(subs))
	for _, sub := range subs {
		fmt.Println(sub)
	}
	fmt.Println()
}

// assetExample 资产测绘示例
func assetExample() {
	fmt.Println("=== 资产测绘 ===")
	opts := &options.Options{
		Agents: []string{"fofa", "quake", "hunter", "shodan"},
		Query: options.Keyword{
			Domain: []string{"example.com"},
		},
		Timeout: 20, // 单个请求超时
	}

	svc, err := cmap.New(opts)
	if err != nil {
		panic(err)
	}

	// 整体查询超时 10 分钟
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	hashMap := make(map[string]bool)
	callback := func(result sources.Result) {
		if result.Error != nil {
			fmt.Printf("[%s] %v\n", result.Source, result.Error)
			return
		}
		index := fmt.Sprintf("%s_%s", result.IP, result.Port)
		if hashMap[index] {
			return
		}
		hashMap[index] = true
		fmt.Printf("[%s] %s %s\n", result.Source, result.PrettyPrint(), result.Title)
	}

	if err := svc.ExecuteAssetWithCallback(ctx, callback); err != nil {
		panic(err)
	}
}
