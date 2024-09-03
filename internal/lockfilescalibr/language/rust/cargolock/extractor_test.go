package cargolock_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/rust/cargolock"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "Empty path",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "Cargo.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.Cargo.lock",
			want:      false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := cargolock.Extractor{}
			got := e.FileRequired(tt.inputPath, nil)
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name:              "Invalid toml",
			inputPath:         "testdata/not-toml.txt",
			WantErrContaining: "could not extract from",
		},
		{
			Name:          "no packages",
			inputPath:     "testdata/empty.lock",
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name:      "one package",
			inputPath: "testdata/one-package.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Locations: []string{"testdata/one-package.lock"},
				},
			},
		},
		{
			Name:      "two packages",
			inputPath: "testdata/two-packages.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Locations: []string{"testdata/two-packages.lock"},
				},
				{
					Name:      "syn",
					Version:   "1.0.73",
					Locations: []string{"testdata/two-packages.lock"},
				},
			},
		},
		{
			Name:      "two packages with local",
			inputPath: "testdata/two-packages-with-local.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "addr2line",
					Version:   "0.15.2",
					Locations: []string{"testdata/two-packages-with-local.lock"},
				},
				{
					Name:      "local-rust-pkg",
					Version:   "0.1.0",
					Locations: []string{"testdata/two-packages-with-local.lock"},
				},
			},
		},
		{
			Name:      "package with build string",
			inputPath: "testdata/package-with-build-string.lock",
			WantInventory: []*extractor.Inventory{
				{
					Name:      "wasi",
					Version:   "0.10.2+wasi-snapshot-preview1",
					Locations: []string{"testdata/package-with-build-string.lock"},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := cargolock.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}
