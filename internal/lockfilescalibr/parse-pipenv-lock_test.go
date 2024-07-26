package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
)

func TestPipenvLockExtractor_FileRequired(t *testing.T) {
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
				path: "Pipfile.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Pipfile.lock",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Pipfile.lock/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path/to/my/Pipfile.lock.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: ScanInputMockConfig{
				path: "path.to.my.Pipfile.lock",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PipenvLockExtractor{}
			got := e.FileRequired(tt.inputConfig.path, GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.path, got, tt.want)
			}
		})
	}
}

func TestPipenvLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid json",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pipenv/not-json.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pipenv/empty.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pipenv/one-package.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"fixtures/pipenv/one-package.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "one package dev",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pipenv/one-package-dev.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"fixtures/pipenv/one-package-dev.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			name: "two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pipenv/two-packages.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "itsdangerous",
					Version:   "2.1.2",
					Locations: []string{"fixtures/pipenv/two-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"fixtures/pipenv/two-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			name: "two packages alt",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pipenv/two-packages-alt.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "itsdangerous",
					Version:   "2.1.2",
					Locations: []string{"fixtures/pipenv/two-packages-alt.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"fixtures/pipenv/two-packages-alt.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "multiple packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pipenv/multiple-packages.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "itsdangerous",
					Version:   "2.1.2",
					Locations: []string{"fixtures/pipenv/multiple-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pluggy",
					Version:   "1.0.1",
					Locations: []string{"fixtures/pipenv/multiple-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pluggy",
					Version:   "1.0.0",
					Locations: []string{"fixtures/pipenv/multiple-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "markupsafe",
					Version:   "2.1.1",
					Locations: []string{"fixtures/pipenv/multiple-packages.json"},
					Metadata: lockfilescalibr.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			name: "package without version",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/pipenv/no-version.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.PipenvLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}