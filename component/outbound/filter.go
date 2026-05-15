/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/dlclark/regexp2"
	"github.com/sirupsen/logrus"
)

const (
	FilterInput_Name            = "name"
	FilterInput_SubscriptionTag = "subtag"
	FilterInput_Link            = "link"
)

const (
	FilterKey_Name_Regex   = "regex"
	FilterKey_Name_Keyword = "keyword"

	FilterInput_SubscriptionTag_Regex = "regex"
)

type DialerSet struct {
	log          *logrus.Logger
	dialers      []*dialer.Dialer
	nodeToTagMap map[*dialer.Dialer]string
}

type compiledFilterParam struct {
	key   string
	val   string
	regex *regexp2.Regexp
}

type compiledFilter struct {
	source *config_parser.Function
	name   string
	not    bool
	params []compiledFilterParam
}

func NewDialerSetFromLinks(option *dialer.GlobalOption, tagToNodeList map[string][]string) *DialerSet {
	s := &DialerSet{
		log:          option.Log,
		dialers:      make([]*dialer.Dialer, 0),
		nodeToTagMap: make(map[*dialer.Dialer]string),
	}
	for subscriptionTag, nodes := range tagToNodeList {
		for _, node := range nodes {
			d, err := dialer.NewFromLink(option, dialer.InstanceOption{DisableCheck: false}, node, subscriptionTag)
			if err != nil {
				s.log.Infof("failed to parse node: %v", err)
				continue
			}
			s.dialers = append(s.dialers, d)
			s.nodeToTagMap[d] = subscriptionTag
		}
	}
	return s
}

func compileFilter(filter *config_parser.Function) compiledFilter {
	c := compiledFilter{
		source: filter,
		name:   filter.Name,
		not:    filter.Not,
		params: make([]compiledFilterParam, 0, len(filter.Params)),
	}
	for _, param := range filter.Params {
		c.params = append(c.params, compiledFilterParam{key: param.Key, val: param.Val})
	}
	return c
}

func compileFilters(filters []*config_parser.Function) []compiledFilter {
	if len(filters) == 0 {
		return nil
	}
	compiled := make([]compiledFilter, 0, len(filters))
	for _, filter := range filters {
		compiled = append(compiled, compileFilter(filter))
	}
	return compiled
}

func compileFilterGroups(filters [][]*config_parser.Function) [][]compiledFilter {
	compiledGroups := make([][]compiledFilter, len(filters))
	for i, group := range filters {
		compiledGroups[i] = compileFilters(group)
	}
	return compiledGroups
}

func (p *compiledFilterParam) matchRegex(s string, filter *config_parser.Function) (bool, error) {
	if p.regex == nil {
		regex, err := regexp2.Compile(p.val, 0)
		if err != nil {
			return false, fmt.Errorf("bad regexp in filter %v: %w", filter.String(false, true, true), err)
		}
		p.regex = regex
	}
	matched, _ := p.regex.MatchString(s)
	return matched, nil
}

func (s *DialerSet) filterHit(dialer *dialer.Dialer, filters []compiledFilter) (bool, error) {
	if len(filters) == 0 {
		// No filter.
		return true, nil
	}

	name := dialer.Property().Name
	subscriptionTag := s.nodeToTagMap[dialer]

	// And
	for filterIdx := range filters {
		filter := &filters[filterIdx]
		var subFilterHit bool

		switch filter.name {
		case FilterInput_Name:
			// Or
		loop:
			for paramIdx := range filter.params {
				param := &filter.params[paramIdx]
				switch param.key {
				case FilterKey_Name_Regex:
					matched, err := param.matchRegex(name, filter.source)
					if err != nil {
						return false, err
					}
					//logrus.Warnln(param.Val, matched, dialer.Name())
					if matched {
						subFilterHit = true
						break loop
					}
				case FilterKey_Name_Keyword:
					if strings.Contains(name, param.val) {
						subFilterHit = true
						break loop
					}
				case "":
					if name == param.val {
						subFilterHit = true
						break loop
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.key, filter.name)
				}
			}
		case FilterInput_SubscriptionTag:
			// Or
		loop2:
			for paramIdx := range filter.params {
				param := &filter.params[paramIdx]
				switch param.key {
				case FilterInput_SubscriptionTag_Regex:
					matched, err := param.matchRegex(subscriptionTag, filter.source)
					if err != nil {
						return false, err
					}
					if matched {
						subFilterHit = true
						break loop2
					}
					//logrus.Warnln(param.Val, matched, dialer.Name())
				case "":
					// Full
					if subscriptionTag == param.val {
						subFilterHit = true
						break loop2
					}
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.key, filter.name)
				}
			}
		default:
			return false, fmt.Errorf(`unsupported filter input type: "%v"`, filter.name)
		}

		if subFilterHit == filter.not {
			return false, nil
		}
	}
	return true, nil
}

func (s *DialerSet) FilterAndAnnotate(filters [][]*config_parser.Function, annotations [][]*config_parser.Param) (dialers []*dialer.Dialer, filterAnnotations []*dialer.Annotation, err error) {
	if len(filters) != len(annotations) {
		return nil, nil, fmt.Errorf("[CODE BUG]: unmatched annotations length: %v filters and %v annotations", len(filters), len(annotations))
	}
	if len(filters) == 0 {
		anno := make([]*dialer.Annotation, len(s.dialers))
		for i := range anno {
			anno[i] = &dialer.Annotation{}
		}
		return s.dialers, anno, nil
	}
	if len(s.dialers) == 0 {
		return nil, nil, nil
	}

	compiledFilterGroups := compileFilterGroups(filters)

nextDialerLoop:
	for _, d := range s.dialers {
		// Hit any.
		for j, f := range compiledFilterGroups {
			hit, err := s.filterHit(d, f)
			if err != nil {
				return nil, nil, err
			}
			if hit {
				anno, err := dialer.NewAnnotation(annotations[j])
				if err != nil {
					return nil, nil, fmt.Errorf("apply filter annotation: %w", err)
				}
				dialers = append(dialers, d)
				filterAnnotations = append(filterAnnotations, anno)
				continue nextDialerLoop
			}
		}
	}
	return dialers, filterAnnotations, nil
}

func (s *DialerSet) Close() error {
	var err error
	for _, d := range s.dialers {
		if e := d.Close(); e != nil {
			err = e
		}
	}
	return err
}
