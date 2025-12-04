package main

import (
	"context"
	"fmt"

	"github.com/404tk/cmap"
	"github.com/404tk/cmap/options"
	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
	_ "github.com/404tk/cmap/sources/plugins"
)

func main() {
	config.SetKeys(config.PlatformFofa, []string{"user@gmail.com:fofa_key"})
	config.SetKeys(config.PlatformHunter, []string{})
	config.SetKeys(config.PlatformQuake, []string{})
	config.SetKeys(config.PlatformShodan, []string{})

	opts := &options.Options{
		Agents: []string{"fofa", "quake", "hunter", "shodan"},
		Query: options.Keyword{
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
			// 基于IP+端口进行去重
			index := fmt.Sprintf("%s_%s", result.IP, result.Port)
			if hashMap[index] {
				return
			}
			hashMap[index] = true
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
