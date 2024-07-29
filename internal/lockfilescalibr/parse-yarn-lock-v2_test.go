package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
)

func TestYarnLockExtractor_Extract_v2(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/empty.v2.lock",
			},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/one-package.v2.lock",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "balanced-match",
					Version:   "1.0.2",
					Locations: []string{"fixtures/yarn/one-package.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/two-packages.v2.lock",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "compare-func",
					Version:   "2.0.0",
					Locations: []string{"fixtures/yarn/two-packages.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "concat-map",
					Version:   "0.0.1",
					Locations: []string{"fixtures/yarn/two-packages.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			name: "with quotes",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/with-quotes.v2.lock",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "compare-func",
					Version:   "2.0.0",
					Locations: []string{"fixtures/yarn/with-quotes.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "concat-map",
					Version:   "0.0.1",
					Locations: []string{"fixtures/yarn/with-quotes.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			name: "multiple versions",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/multiple-versions.v2.lock",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "debug",
					Version:   "4.3.3",
					Locations: []string{"fixtures/yarn/multiple-versions.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "debug",
					Version:   "2.6.9",
					Locations: []string{"fixtures/yarn/multiple-versions.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "debug",
					Version:   "3.2.7",
					Locations: []string{"fixtures/yarn/multiple-versions.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			name: "scoped packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/scoped-packages.v2.lock",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "@babel/cli",
					Version:   "7.16.8",
					Locations: []string{"fixtures/yarn/scoped-packages.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "@babel/code-frame",
					Version:   "7.16.7",
					Locations: []string{"fixtures/yarn/scoped-packages.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "@babel/compat-data",
					Version:   "7.16.8",
					Locations: []string{"fixtures/yarn/scoped-packages.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			name: "with prerelease",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/with-prerelease.v2.lock",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "@nicolo-ribaudo/chokidar-2",
					Version:   "2.1.8-no-fsevents.3",
					Locations: []string{"fixtures/yarn/with-prerelease.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "gensync",
					Version:   "1.0.0-beta.2",
					Locations: []string{"fixtures/yarn/with-prerelease.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "eslint-plugin-jest",
					Version:   "0.0.0-use.local",
					Locations: []string{"fixtures/yarn/with-prerelease.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			name: "with build string",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/with-build-string.v2.lock",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "domino",
					Version:   "2.1.6+git",
					Locations: []string{"fixtures/yarn/with-build-string.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a",
					},
				},
				{
					Name:      "tslib",
					Version:   "2.6.2",
					Locations: []string{"fixtures/yarn/with-build-string.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "zone.js",
					Version:   "0.0.0-use.local",
					Locations: []string{"fixtures/yarn/with-build-string.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			name: "commits",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/commits.v2.lock",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "@my-scope/my-first-package",
					Version:   "0.0.6",
					Locations: []string{"fixtures/yarn/commits.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0b824c650d3a03444dbcf2b27a5f3566f6e41358",
					},
				},
				{
					Name:      "my-second-package",
					Version:   "0.2.2",
					Locations: []string{"fixtures/yarn/commits.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "59e2127b9f9d4fda5f928c4204213b3502cd5bb0",
					},
				},
				{
					Name:      "@typegoose/typegoose",
					Version:   "7.2.0",
					Locations: []string{"fixtures/yarn/commits.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "3ed06e5097ab929f69755676fee419318aaec73a",
					},
				},
				{
					Name:      "vuejs",
					Version:   "2.5.0",
					Locations: []string{"fixtures/yarn/commits.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0948d999f2fddf9f90991956493f976273c5da1f",
					},
				},
				{
					Name:      "my-third-package",
					Version:   "0.16.1-dev",
					Locations: []string{"fixtures/yarn/commits.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "5675a0aed98e067ff6ecccc5ac674fe8995960e0",
					},
				},
				{
					Name:      "my-node-sdk",
					Version:   "1.1.0",
					Locations: []string{"fixtures/yarn/commits.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "053dea9e0b8af442d8f867c8e690d2fb0ceb1bf5",
					},
				},
				{
					Name:      "is-really-great",
					Version:   "1.0.0",
					Locations: []string{"fixtures/yarn/commits.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "191eeef50c584714e1fb8927d17ee72b3b8c97c4",
					},
				},
			},
		},
		{
			name: "files",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/files.v2.lock",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "my-package",
					Version:   "0.0.2",
					Locations: []string{"fixtures/yarn/files.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			name: "with aliases",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/yarn/with-aliases.v2.lock",
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:      "@babel/helper-validator-identifier",
					Version:   "7.22.20",
					Locations: []string{"fixtures/yarn/with-aliases.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "ansi-regex",
					Version:   "6.0.1",
					Locations: []string{"fixtures/yarn/with-aliases.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "ansi-regex",
					Version:   "5.0.1",
					Locations: []string{"fixtures/yarn/with-aliases.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "mine",
					Version:   "0.0.0-use.local",
					Locations: []string{"fixtures/yarn/with-aliases.v2.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.YarnLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
