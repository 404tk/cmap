package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"

	"github.com/404tk/cmap"
	"github.com/404tk/cmap/options"
	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
	"github.com/404tk/cmap/sources/plugins"
)

var configPath = "config.yaml"

func main() {
	config.InitConfig(configPath)
	opts := &options.Options{
		Agents: []string{"fofa", "quake", "hunter", "shodan"},
		Query: plugins.Keyword{
			Domain: []string{"cnblogs.com"},
		},
		Timeout: 20,
	}

	u, err := cmap.New(opts)
	if err != nil {
		panic(err)
	}

	hashMap := make(map[string]bool)
	result := func(result sources.Result) {
		if result.Error != nil {
			fmt.Printf("[%s] %v\n", result.Source, result.Error)
		} else {
			// 基于IP、端口生成唯一hash进行去重
			index := generateHash(fmt.Sprintf("%s_%s", result.IP, result.Port))
			if !hashMap[index] {
				hashMap[index] = true
			}
			// result.Url
			fmt.Printf("[%s] %s %s\n", result.Source, result.PrettyPrint(), result.Title)
		}
	}

	// Execute executes and returns a channel with all results
	// ch , err := u.Execute(context.Background())

	// Execute with Callback calls u.Execute() internally and abstracts channel handling logic
	if err := u.ExecuteWithCallback(context.TODO(), result); err != nil {
		panic(err)
	}
}

func generateHash(s string) string {
	hasher := md5.New()
	hasher.Write([]byte(s))
	return hex.EncodeToString(hasher.Sum(nil))
}
