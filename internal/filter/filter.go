package filter

import (
	"bufio"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/kohanmathers/kmresolv/internal/config"
	"github.com/kohanmathers/kmresolv/internal/logger"
)

type filterState struct {
	domains map[string]bool
	mode    string
}

type Filter struct {
	state  atomic.Pointer[filterState]
	wmu    sync.Mutex
	inline map[string]bool
}

func NewFilter(cfg *config.Config) *Filter {
	f := &Filter{
		inline: make(map[string]bool),
	}
	mode := strings.ToLower(cfg.Filtering.Mode)
	domains := make(map[string]bool)

	if mode != "off" {
		for _, d := range cfg.Filtering.Inline {
			d = strings.ToLower(strings.TrimSpace(d))
			domains[d] = true
			f.inline[d] = true
		}
		for _, source := range cfg.Filtering.Lists {
			if err := loadListFromSource(source, domains); err != nil {
				logger.LogWarn("failed to load filter list %s: %v", source, err)
			}
		}
		logger.LogInfo("filter loaded: mode=%s domains=%d", mode, len(domains))
	}

	f.state.Store(&filterState{domains: domains, mode: mode})
	return f
}

func (f *Filter) Blocked(name string) bool {
	st := f.state.Load()
	if st.mode == "off" {
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for {
		if st.domains[name] {
			return st.mode == "blacklist"
		}
		idx := strings.Index(name, ".")
		if idx == -1 {
			break
		}
		name = name[idx+1:]
	}
	return st.mode == "whitelist"
}

func (f *Filter) Add(domain string) {
	d := strings.ToLower(strings.TrimSpace(domain))
	f.wmu.Lock()
	defer f.wmu.Unlock()
	cur := f.state.Load()
	next := copyDomains(cur.domains)
	next[d] = true
	f.inline[d] = true
	f.state.Store(&filterState{domains: next, mode: cur.mode})
}

func (f *Filter) Remove(domain string) {
	d := strings.ToLower(strings.TrimSpace(domain))
	f.wmu.Lock()
	defer f.wmu.Unlock()
	cur := f.state.Load()
	next := copyDomains(cur.domains)
	delete(next, d)
	delete(f.inline, d)
	f.state.Store(&filterState{domains: next, mode: cur.mode})
}

func (f *Filter) SetMode(mode string) {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	cur := f.state.Load()
	f.state.Store(&filterState{domains: cur.domains, mode: strings.ToLower(mode)})
}

func (f *Filter) Size() int {
	return len(f.state.Load().domains)
}

func (f *Filter) InlineDomains() []string {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	out := make([]string, 0, len(f.inline))
	for d := range f.inline {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func (f *Filter) Reload(cfg *config.Config) {
	mode := strings.ToLower(cfg.Filtering.Mode)

	loaded := make(map[string]bool)
	if mode != "off" {
		for _, source := range cfg.Filtering.Lists {
			if err := loadListFromSource(source, loaded); err != nil {
				logger.LogWarn("failed to reload filter list %s: %v", source, err)
			}
		}
	}

	f.wmu.Lock()
	defer f.wmu.Unlock()
	domains := make(map[string]bool, len(loaded)+len(f.inline))
	for d := range loaded {
		domains[d] = true
	}
	for d := range f.inline {
		domains[d] = true
	}
	f.state.Store(&filterState{domains: domains, mode: mode})
	logger.LogInfo("filter reloaded: mode=%s domains=%d", mode, len(domains))
}

func copyDomains(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func loadListFromSource(source string, domains map[string]bool) error {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return loadFromURL(source, domains)
	}
	return loadFromFile(source, domains)
}

func loadFromURL(url string, domains map[string]bool) error {
	logger.LogInfo("fetching filter list: %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	parseList(bufio.NewScanner(resp.Body), domains)
	return nil
}

func loadFromFile(path string, domains map[string]bool) error {
	logger.LogInfo("loading filter list: %s", path)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	parseList(bufio.NewScanner(file), domains)
	return nil
}

func parseList(scanner *bufio.Scanner, domains map[string]bool) {
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		switch len(fields) {
		case 1:
			domains[strings.ToLower(fields[0])] = true
		case 2:
			domain := strings.ToLower(fields[1])
			if domain != "localhost" && domain != "localhost.localdomain" {
				domains[domain] = true
			}
		}
	}
}
