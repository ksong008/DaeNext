/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config_parser

import (
	"fmt"
	"github.com/antlr/antlr4/runtime/Go/antlr/v4"
	"github.com/daeuniverse/dae-config-dist/go/dae_config"
)

func recoveredParseError(recovered any) error {
	if err, ok := recovered.(error); ok {
		return fmt.Errorf("parse config: %w", err)
	}
	return fmt.Errorf("parse config: unexpected internal parser state: %v", recovered)
}

func Parse(in string) (sections []*Section, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			sections = nil
			err = recoveredParseError(recovered)
		}
	}()

	errorListener := NewConsoleErrorListener()
	lexer := dae_config.Newdae_configLexer(antlr.NewInputStream(in))
	lexer.RemoveErrorListeners()
	lexer.AddErrorListener(errorListener)
	input := antlr.NewCommonTokenStream(lexer, 0)

	parser := dae_config.Newdae_configParser(input)
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errorListener)
	parser.BuildParseTrees = true
	tree := parser.Start()

	walker := NewWalker(parser)
	antlr.ParseTreeWalkerDefault.Walk(walker, tree)
	if errorListener.ErrorBuilder.Len() != 0 {
		return nil, fmt.Errorf("%v", errorListener.ErrorBuilder.String())
	}

	return walker.Sections, nil
}
