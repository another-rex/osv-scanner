package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
)

func TestPnpmLockExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "pnpm-lock.yaml",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/pnpm-lock.yaml",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/pnpm-lock.yaml/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/pnpm-lock.yaml.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.pnpm-lock.yaml",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PnpmLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestPnpmLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid yaml",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/not-yaml.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "empty",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/empty.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/no-packages.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/one-package.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"fixtures/pnpm/one-package.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "one package v6 lockfile",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/one-package-v6-lockfilescalibr.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"fixtures/pnpm/one-package-v6-lockfilescalibr.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "one package dev",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/one-package-dev.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"fixtures/pnpm/one-package-dev.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "scoped packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/scoped-packages.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.13.0",
					Locations:  []string{"fixtures/pnpm/scoped-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "scoped packages v6 lockfile",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/scoped-packages-v6-lockfilescalibr.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.57.1",
					Locations:  []string{"fixtures/pnpm/scoped-packages-v6-lockfilescalibr.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "peer dependencies",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/peer-dependencies.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					Locations:  []string{"fixtures/pnpm/peer-dependencies.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "peer dependencies advanced",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/peer-dependencies-advanced.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "@typescript-eslint/eslint-plugin",
					Version:    "5.13.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/parser",
					Version:    "5.13.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/type-utils",
					Version:    "5.13.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.13.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/typescript-estree",
					Version:    "5.13.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/utils",
					Version:    "5.13.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "eslint-utils",
					Version:    "3.0.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "eslint",
					Version:    "8.10.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "tsutils",
					Version:    "3.21.0",
					Locations:  []string{"fixtures/pnpm/peer-dependencies-advanced.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "multiple packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/multiple-packages.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "aws-sdk",
					Version:    "2.1087.0",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "base64-js",
					Version:    "1.5.1",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "buffer",
					Version:    "4.9.2",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "events",
					Version:    "1.1.1",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "ieee754",
					Version:    "1.1.13",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "isarray",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "jmespath",
					Version:    "0.16.0",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "punycode",
					Version:    "1.3.2",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "querystring",
					Version:    "0.2.0",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "sax",
					Version:    "1.2.1",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "url",
					Version:    "0.10.3",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "3.3.2",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xml2js",
					Version:    "0.4.19",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xmlbuilder",
					Version:    "9.0.7",
					Locations:  []string{"fixtures/pnpm/multiple-packages.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "multiple versions",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/multiple-versions.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "uuid",
					Version:    "3.3.2",
					Locations:  []string{"fixtures/pnpm/multiple-versions.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					Locations:  []string{"fixtures/pnpm/multiple-versions.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xmlbuilder",
					Version:    "9.0.7",
					Locations:  []string{"fixtures/pnpm/multiple-versions.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "tarball",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/tarball.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "@my-org/my-package",
					Version:    "3.2.3",
					Locations:  []string{"fixtures/pnpm/tarball.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			name: "exotic",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/exotic.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "foo",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/pnpm/exotic.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@foo/bar",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/pnpm/exotic.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.1.0",
					Locations:  []string{"fixtures/pnpm/exotic.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@foo/bar",
					Version:    "1.1.0",
					Locations:  []string{"fixtures/pnpm/exotic.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.2.0",
					Locations:  []string{"fixtures/pnpm/exotic.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.3.0",
					Locations:  []string{"fixtures/pnpm/exotic.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.4.0",
					Locations:  []string{"fixtures/pnpm/exotic.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "commits",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/commits.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "my-bitbucket-package",
					Version:   "1.0.0",
					Locations: []string{"fixtures/pnpm/commits.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "6104ae42cd32c3d724036d3964678f197b2c9cdb",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "@my-scope/my-package",
					Version:   "1.0.0",
					Locations: []string{"fixtures/pnpm/commits.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "267087851ad5fac92a184749c27cd539e2fc862e",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "@my-scope/my-other-package",
					Version:   "1.0.0",
					Locations: []string{"fixtures/pnpm/commits.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "fbfc962ab51eb1d754749b68c064460221fbd689",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "faker-parser",
					Version:   "0.0.1",
					Locations: []string{"fixtures/pnpm/commits.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "d2dc42a9351d4d89ec48c525e34f612b6d77993f",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "mocks",
					Version:   "20.0.1",
					Locations: []string{"fixtures/pnpm/commits.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{
						Commit: "590f321b4eb3f692bb211bd74e22947639a6f79d",
					},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "files",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pnpm/files.yaml",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:       "my-file-package",
					Version:    "0.0.0",
					Locations:  []string{"fixtures/pnpm/files.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "a-local-package",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/pnpm/files.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "a-nested-local-package",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/pnpm/files.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "one-up",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/pnpm/files.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "one-up-with-peer",
					Version:    "1.0.0",
					Locations:  []string{"fixtures/pnpm/files.yaml"},
					SourceCode: &lockfilescalibr.SourceCodeIdentifier{},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PnpmLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}

// func TestParsePnpmLock_InvalidYaml(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/not-yaml.txt")

// 	expectErrContaining(t, err, "could not extract from")
// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{})
// }

// func TestParsePnpmLock_Empty(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/empty.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{})
// }

// func TestParsePnpmLock_NoPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/no-packages.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{})
// }

// func TestParsePnpmLock_OnePackage(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/one-package.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "acorn",
// 			Version:   "8.7.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 	})
// }

// func TestParsePnpmLock_OnePackageV6Lockfile(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/one-package-v6-lockfilescalibr.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "acorn",
// 			Version:   "8.7.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 	})
// }

// func TestParsePnpmLock_OnePackageDev(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/one-package-dev.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "acorn",
// 			Version:   "8.7.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 	})
// }

// func TestParsePnpmLock_ScopedPackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/scoped-packages.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "@typescript-eslint/types",
// 			Version:   "5.13.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 	})
// }

// func TestParsePnpmLock_ScopedPackagesV6Lockfile(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/scoped-packages-v6-lockfilescalibr.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "@typescript-eslint/types",
// 			Version:   "5.57.1",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 	})
// }

// func TestParsePnpmLock_PeerDependencies(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/peer-dependencies.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "acorn-jsx",
// 			Version:   "5.3.2",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "acorn",
// 			Version:   "8.7.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 	})
// }

// func TestParsePnpmLock_PeerDependenciesAdvanced(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/peer-dependencies-advanced.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "@typescript-eslint/eslint-plugin",
// 			Version:   "5.13.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "@typescript-eslint/parser",
// 			Version:   "5.13.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "@typescript-eslint/type-utils",
// 			Version:   "5.13.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "@typescript-eslint/types",
// 			Version:   "5.13.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "@typescript-eslint/typescript-estree",
// 			Version:   "5.13.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "@typescript-eslint/utils",
// 			Version:   "5.13.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "eslint-utils",
// 			Version:   "3.0.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "eslint",
// 			Version:   "8.10.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "tsutils",
// 			Version:   "3.21.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 	})
// }

// func TestParsePnpmLock_MultiplePackages(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/multiple-packages.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "aws-sdk",
// 			Version:   "2.1087.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "base64-js",
// 			Version:   "1.5.1",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "buffer",
// 			Version:   "4.9.2",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "events",
// 			Version:   "1.1.1",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "ieee754",
// 			Version:   "1.1.13",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "isarray",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "jmespath",
// 			Version:   "0.16.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "punycode",
// 			Version:   "1.3.2",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "querystring",
// 			Version:   "0.2.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "sax",
// 			Version:   "1.2.1",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "url",
// 			Version:   "0.10.3",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "uuid",
// 			Version:   "3.3.2",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "xml2js",
// 			Version:   "0.4.19",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "xmlbuilder",
// 			Version:   "9.0.7",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 	})
// }

// func TestParsePnpmLock_MultipleVersions(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/multiple-versions.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "uuid",
// 			Version:   "3.3.2",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "uuid",
// 			Version:   "8.3.2",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "xmlbuilder",
// 			Version:   "9.0.7",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 	})
// }

// func TestParsePnpmLock_Tarball(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/tarball.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "@my-org/my-package",
// 			Version:   "3.2.3",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 			Commit:    "",
// 			DepGroups: []string{"dev"},
// 		},
// 	})
// }

// func TestParsePnpmLock_Exotic(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/exotic.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "foo",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "@foo/bar",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "foo",
// 			Version:   "1.1.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "@foo/bar",
// 			Version:   "1.1.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "foo",
// 			Version:   "1.2.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "foo",
// 			Version:   "1.3.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 		{
// 			Name:      "foo",
// 			Version:   "1.4.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 		},
// 	})
// }

// func TestParsePnpmLock_Commits(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/commits.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "my-bitbucket-package",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 			Commit:    "6104ae42cd32c3d724036d3964678f197b2c9cdb",
// 		},
// 		{
// 			Name:      "@my-scope/my-package",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 			Commit:    "267087851ad5fac92a184749c27cd539e2fc862e",
// 		},
// 		{
// 			Name:      "@my-scope/my-other-package",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 			Commit:    "fbfc962ab51eb1d754749b68c064460221fbd689",
// 		},
// 		{
// 			Name:      "faker-parser",
// 			Version:   "0.0.1",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 			Commit:    "d2dc42a9351d4d89ec48c525e34f612b6d77993f",
// 		},
// 		{
// 			Name:      "mocks",
// 			Version:   "20.0.1",
// 			Ecosystem: lockfilescalibr.PnpmEcosystem,
// 			CompareAs: lockfilescalibr.PnpmEcosystem,
// 			Commit:    "590f321b4eb3f692bb211bd74e22947639a6f79d",
// 		},
// 	})
// }

// func TestParsePnpmLock_Files(t *testing.T) {
// 	t.Parallel()

// 	packages, err := lockfilescalibr.ParsePnpmLock("fixtures/pnpm/files.yaml")

// 	if err != nil {
// 		t.Errorf("Got unexpected error: %v", err)
// 	}

// 	expectPackages(t, packages, []lockfilescalibr.PackageDetails{
// 		{
// 			Name:      "my-file-package",
// 			Version:   "0.0.0",
// 			Ecosystem: lockfilescalibr.NpmEcosystem,
// 			CompareAs: lockfilescalibr.NpmEcosystem,
// 			Commit:    "",
// 		},
// 		{
// 			Name:      "a-local-package",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfilescalibr.NpmEcosystem,
// 			CompareAs: lockfilescalibr.NpmEcosystem,
// 			Commit:    "",
// 		},
// 		{
// 			Name:      "a-nested-local-package",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfilescalibr.NpmEcosystem,
// 			CompareAs: lockfilescalibr.NpmEcosystem,
// 			Commit:    "",
// 		},
// 		{
// 			Name:      "one-up",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfilescalibr.NpmEcosystem,
// 			CompareAs: lockfilescalibr.NpmEcosystem,
// 			Commit:    "",
// 		},
// 		{
// 			Name:      "one-up-with-peer",
// 			Version:   "1.0.0",
// 			Ecosystem: lockfilescalibr.NpmEcosystem,
// 			CompareAs: lockfilescalibr.NpmEcosystem,
// 			Commit:    "",
// 		},
// 	})
// }