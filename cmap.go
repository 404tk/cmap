package cmap

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/404tk/cmap/options"
	"github.com/404tk/cmap/sources"
	"github.com/404tk/cmap/sources/config"
	"github.com/404tk/cmap/sources/plugins"
)

var DefaultChannelBuffSize = 32

type Service struct {
	Options *options.Options
	Plugins []plugins.Plugin
	Session *sources.Session
}

func New(opts *options.Options) (*Service, error) {
	s := &Service{Options: opts}
	if len(opts.Agents) == 0 {
		return nil, fmt.Errorf("no agent/source specified")
	}
	for _, agent := range opts.Agents {
		if v, ok := plugins.Plugins[agent]; ok {
			s.Plugins = append(s.Plugins, v)
		}
	}

	if opts.Timeout == 0 {
		opts.Timeout = 30
	}
	if opts.RateLimit == 0 {
		opts.RateLimit = 30
	}
	if opts.RateLimitUnit == 0 {
		opts.RateLimitUnit = time.Minute
	}

	var err error
	s.Session, err = sources.NewSession(opts)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) ExecuteAsset(ctx context.Context) (<-chan sources.Result, error) {
	// unlikely but as a precaution to handle random panics check all types
	if err := s.nilCheck(); err != nil {
		return nil, err
	}

	megaChan := make(chan sources.Result, DefaultChannelBuffSize)
	// iterate and run all sources
	wg := &sync.WaitGroup{}
	for _, plugin := range s.Plugins {
		ch, err := plugin.QueryAsset(ctx, s.Session, s.Options.Query)
		if err != nil {
			log.Printf("[%s] %v\n", plugin.Name(), err)
			continue
		}
		if ch == nil {
			// 该插件不支持资产测绘
			continue
		}
		wg.Add(1)
		go func(source, relay chan sources.Result, ctx context.Context) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case res, ok := <-source:
					res.Timestamp = time.Now().Unix()
					if !ok {
						return
					}
					relay <- res
				}
			}
		}(ch, megaChan, ctx)
	}

	// close channel when all sources return
	go func(wg *sync.WaitGroup, megaChan chan sources.Result) {
		wg.Wait()
		defer close(megaChan)
	}(wg, megaChan)

	return megaChan, nil
}

// ExecuteSubdomain 执行子域名收集，返回流式 channel
func (s *Service) ExecuteSubdomain(ctx context.Context) (<-chan string, error) {
	if err := s.nilCheck(); err != nil {
		return nil, err
	}

	k, ok := s.Options.Query.(options.Keyword)
	if !ok || len(k.Domain) == 0 {
		return nil, fmt.Errorf("no domain specified in query")
	}

	megaChan := make(chan string, DefaultChannelBuffSize)
	wg := &sync.WaitGroup{}

	for _, plugin := range s.Plugins {
		for _, domain := range k.Domain {
			ch, err := plugin.QuerySubdomain(ctx, s.Session, domain)
			if err != nil {
				log.Printf("[%s] %v\n", plugin.Name(), err)
				continue
			}
			if ch == nil {
				// 该插件不支持子域名收集
				continue
			}
			wg.Add(1)
			go func(source chan string, relay chan string, ctx context.Context) {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case sub, ok := <-source:
						if !ok {
							return
						}
						relay <- sub
					}
				}
			}(ch, megaChan, ctx)
		}
	}

	go func(wg *sync.WaitGroup, megaChan chan string) {
		wg.Wait()
		close(megaChan)
	}(wg, megaChan)

	return megaChan, nil
}

// ExecuteSubdomainUnique 执行子域名收集，返回去重后的子域名列表
// 当 ctx 超时时返回已收集到的结果
func (s *Service) ExecuteSubdomainUnique(ctx context.Context) ([]string, error) {
	ch, err := s.ExecuteSubdomain(ctx)
	if err != nil {
		return nil, err
	}

	unique := make(map[string]struct{})
	for {
		select {
		case <-ctx.Done():
			// 超时，返回已收集到的结果
			result := make([]string, 0, len(unique))
			for sub := range unique {
				result = append(result, sub)
			}
			return result, nil
		case sub, ok := <-ch:
			if !ok {
				// channel 关闭，所有结果已收集完毕
				result := make([]string, 0, len(unique))
				for sub := range unique {
					result = append(result, sub)
				}
				return result, nil
			}
			unique[sub] = struct{}{}
		}
	}
}

// ExecuteAssetWithCallback 资产测绘带回调
func (s *Service) ExecuteAssetWithCallback(ctx context.Context, callback func(result sources.Result)) error {
	ch, err := s.ExecuteAsset(ctx)
	if err != nil {
		return err
	}
	if callback == nil {
		return fmt.Errorf("result callback cannot be nil")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case result, ok := <-ch:
			if !ok {
				return nil
			}
			callback(result)
		}
	}
}

func (s *Service) nilCheck() error {
	if s.Options == nil {
		return fmt.Errorf("options cannot be nil")
	}
	if s.Session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	return nil
}

// VerifyKeys 验证所有配置的平台凭据
// 返回 map[platform][]KeyStatus
func (s *Service) VerifyKeys() map[string][]config.KeyStatus {
	results := make(map[string][]config.KeyStatus)
	for _, plugin := range s.Plugins {
		statuses := plugin.VerifyKeys(s.Session)
		if len(statuses) > 0 {
			results[plugin.Name()] = statuses
		}
	}
	return results
}
