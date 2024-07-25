package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestPoetryLockExtractor_ShouldExtract(t *testing.T) {
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
				path: "poetry.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/poetry.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/poetry.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/poetry.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.poetry.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.PoetryLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestPoetryLockExtractor_Extract(t *testing.T) {
	t.Parallel()
	tests := []testTableEntry{
		{
			name: "invalid toml",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/poetry/not-toml.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/poetry/empty.lock",
			},
			wantInventory: []*lockfile.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/poetry/one-package.lock",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "numpy",
					Version:   "1.23.3",
					Locations: []string{"fixtures/poetry/one-package.lock"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/poetry/two-packages.lock",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "proto-plus",
					Version:   "1.22.0",
					Locations: []string{"fixtures/poetry/two-packages.lock"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "protobuf",
					Version:   "4.21.5",
					Locations: []string{"fixtures/poetry/two-packages.lock"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "package with metadata",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/poetry/one-package-with-metadata.lock",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "emoji",
					Version:   "2.0.0",
					Locations: []string{"fixtures/poetry/one-package-with-metadata.lock"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "package with git source",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/poetry/source-git.lock",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "ike",
					Version:   "0.2.0",
					Locations: []string{"fixtures/poetry/source-git.lock"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "cd66602cd29f61a2d2e7fb995fef1e61708c034d",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "package with legacy source",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/poetry/source-legacy.lock",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "appdirs",
					Version:   "1.4.4",
					Locations: []string{"fixtures/poetry/source-legacy.lock"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "optional package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/poetry/optional-package.lock",
			},
			wantInventory: []*lockfile.Inventory{
				{
					Name:      "numpy",
					Version:   "1.23.3",
					Locations: []string{"fixtures/poetry/optional-package.lock"},
					SourceCode: &lockfile.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: lockfile.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfile.PoetryLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}
