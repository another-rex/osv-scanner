package pnpmlock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/javascript/pnpmlock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_Extract_v9(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/no-packages.v9.yaml",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/one-package.v9.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn",
					Version:    "8.11.3",
					Locations:  []string{"testdata/one-package.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/one-package-dev.v9.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn",
					Version:    "8.11.3",
					Locations:  []string{"testdata/one-package-dev.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "scoped packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/scoped-packages.v9.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.62.0",
					Locations:  []string{"testdata/scoped-packages.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer dependencies",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/peer-dependencies.v9.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					Locations:  []string{"testdata/peer-dependencies.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.11.3",
					Locations:  []string{"testdata/peer-dependencies.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer dependencies advanced",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/peer-dependencies-advanced.v9.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "@eslint-community/eslint-utils",
					Version:    "4.4.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@eslint/eslintrc",
					Version:    "2.1.4",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/eslint-plugin",
					Version:    "5.62.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/parser",
					Version:    "5.62.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/type-utils",
					Version:    "5.62.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/typescript-estree",
					Version:    "5.62.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/utils",
					Version:    "5.62.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "debug",
					Version:    "4.3.4",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "eslint",
					Version:    "8.57.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "7.2.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "tsutils",
					Version:    "3.21.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "typescript",
					Version:    "4.9.5",
					Locations:  []string{"testdata/peer-dependencies-advanced.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "multiple versions",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/multiple-versions.v9.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "uuid",
					Version:    "8.0.0",
					Locations:  []string{"testdata/multiple-versions.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					Locations:  []string{"testdata/multiple-versions.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xmlbuilder",
					Version:    "11.0.1",
					Locations:  []string{"testdata/multiple-versions.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "commits",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/commits.v9.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "ansi-regex",
					Version:   "6.0.1",
					Locations: []string{"testdata/commits.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "02fa893d619d3da85411acc8fd4e2eea0e95a9d9",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number",
					Version:   "7.0.0",
					Locations: []string{"testdata/commits.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "98e8ff1da1a89f93d1397a24d7413ed15421c139",
					},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "mixed groups",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/mixed-groups.v9.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "ansi-regex",
					Version:    "5.0.1",
					Locations:  []string{"testdata/mixed-groups.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					Locations:  []string{"testdata/mixed-groups.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "is-number",
					Version:    "7.0.0",
					Locations:  []string{"testdata/mixed-groups.v9.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := pnpmlock.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}