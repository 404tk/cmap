package cmap

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/404tk/cmap/options"
	"github.com/404tk/cmap/sources"
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

func (s *Service) Execute(ctx context.Context) (<-chan sources.Result, error) {
	// unlikely but as a precaution to handle random panics check all types
	if err := s.nilCheck(); err != nil {
		return nil, err
	}

	if len(s.Plugins) == 0 {
		return nil, fmt.Errorf("no agent/source specified")
	}

	megaChan := make(chan sources.Result, DefaultChannelBuffSize)
	// iterate and run all sources
	wg := &sync.WaitGroup{}
	for _, plugin := range s.Plugins {
		ch, err := plugin.Query(s.Session, s.Options.Query)
		if err != nil {
			log.Printf("[%s] %v\n", plugin.Name(), err)
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

// ExecuteWithWriters writes output to writer along with stdout
func (s *Service) ExecuteWithCallback(ctx context.Context, callback func(result sources.Result)) error {
	ch, err := s.Execute(ctx)
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
