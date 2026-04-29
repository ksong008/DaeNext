/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package engine

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/mohae/deepcopy"
)

const (
	EmptyGroupSection        = `group {}`
	EmptySubscriptionSection = `subscription {}`
	EmptyNodeSection         = `node {}`
	EmptyRoutingSection      = `routing {}`
	EmptyDnsSection          = `dns {}`
	EmptyGlobalSection       = `global {}`
)

var emptyConfigTemplate = mustBuildEmptyConfig()

type FlatDesc struct {
	Name         string `json:"name,omitempty"`
	Mapping      string `json:"mapping,omitempty"`
	IsArray      bool   `json:"isArray,omitempty"`
	DefaultValue string `json:"defaultValue,omitempty"`
	Required     bool   `json:"required,omitempty"`
	Type         string `json:"type,omitempty"`
	Desc         string `json:"desc,omitempty"`
}

func mustBuildEmptyConfig() *config.Config {
	sections, err := config_parser.Parse(`global{} routing{}`)
	if err != nil {
		panic(err)
	}
	conf, err := config.New(sections)
	if err != nil {
		panic(err)
	}
	return conf
}

func EmptyConfig() *config.Config {
	return deepcopy.Copy(emptyConfigTemplate).(*config.Config)
}

func ReadConfigFile(cfgFile string) (conf *config.Config, includes []string, err error) {
	merger := config.NewMerger(cfgFile)
	sections, includes, err := merger.Merge()
	if err != nil {
		return nil, nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, nil, err
	}
	return conf, includes, nil
}

func ParseConfig(globalSection *string, dnsSection *string, routingSection *string) (*config.Config, error) {
	if globalSection == nil {
		globalSection = refString(EmptyGlobalSection)
	}
	if dnsSection == nil {
		dnsSection = refString(EmptyDnsSection)
	}
	if routingSection == nil {
		routingSection = refString(EmptyRoutingSection)
	}
	strConfig := strings.Join([]string{
		*globalSection,
		*dnsSection,
		*routingSection,
		EmptyGroupSection,
		EmptySubscriptionSection,
		EmptyNodeSection,
	}, "\n")
	sections, err := config_parser.Parse(strConfig)
	if err != nil {
		return nil, err
	}
	return config.New(sections)
}

func NecessaryOutbounds(routing *config.Routing) (outbounds []string) {
	f := config.FunctionOrStringToFunction(routing.Fallback)
	outbounds = append(outbounds, f.Name)
	for _, r := range routing.Rules {
		outbound := r.Outbound.Name
		if outbound != "must_rules" {
			outbound = strings.TrimPrefix(outbound, "must_")
		}
		outbounds = append(outbounds, outbound)
	}
	return common.Deduplicate(outbounds)
}

func ExportFlatDesc() []*FlatDesc {
	t := reflect.TypeOf(config.Config{})
	exporter := flatDescExporter{
		leaves:       make(map[string]reflect.Type),
		pkgPathScope: t.PkgPath(),
	}
	return exporter.exportStruct("", "", t, config.SectionSummaryDesc, false)
}

func preprocessWanInterfaceAuto(params *config.Config) error {
	ifs := make([]string, 0, len(params.Global.WanInterface)+2)
	for _, ifname := range params.Global.WanInterface {
		if ifname == "auto" {
			defaultIfs, err := common.GetDefaultIfnames()
			if err != nil {
				return fmt.Errorf("failed to convert 'auto': %w", err)
			}
			ifs = append(ifs, defaultIfs...)
		} else {
			ifs = append(ifs, ifname)
		}
	}
	params.Global.WanInterface = common.Deduplicate(ifs)
	return nil
}

func refString(value string) *string {
	return &value
}

type flatDescExporter struct {
	leaves       map[string]reflect.Type
	pkgPathScope string
}

func (e *flatDescExporter) exportStruct(namePrefix string, mappingPrefix string, t reflect.Type, descSource config.Desc, inheritSource bool) (descList []*FlatDesc) {
	for i := 0; i < t.NumField(); i++ {
		section := t.Field(i)
		mapping := section.Tag.Get("mapstructure")
		var desc string
		if descSource != nil {
			desc = descSource[mapping]
		}
		var isArray bool
		var typ reflect.Type
		switch section.Type.Kind() {
		case reflect.Slice:
			typ = section.Type.Elem()
			isArray = true
		default:
			typ = section.Type
		}
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		var children []*FlatDesc
		switch typ.Kind() {
		case reflect.Struct:
			var nextDescSource config.Desc
			if inheritSource {
				nextDescSource = descSource
			} else {
				nextDescSource = config.SectionDescription[section.Tag.Get("desc")]
			}
			if typ.PkgPath() == "" || typ.PkgPath() == e.pkgPathScope {
				children = e.exportStruct(
					namePrefix+section.Name+".",
					mappingPrefix+mapping+".",
					typ,
					nextDescSource,
					true,
				)
			}
		}
		if len(children) == 0 {
			e.leaves[typ.String()] = typ
		}
		_, required := section.Tag.Lookup("required")
		descList = append(descList, &FlatDesc{
			Name:         namePrefix + section.Name,
			Mapping:      mappingPrefix + mapping,
			IsArray:      isArray,
			DefaultValue: section.Tag.Get("default"),
			Required:     required,
			Type:         typ.String(),
			Desc:         desc,
		})
		descList = append(descList, children...)
	}
	return descList
}
