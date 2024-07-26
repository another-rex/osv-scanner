package lockfilescalibr_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr"
)

func TestNuGetLockExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []testTableEntry{
		{
			name: "invalid json",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/nuget/not-json.txt",
			},
			wantErrContaining: "could not extract from",
		},
		{
			name: "no packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/nuget/empty.v1.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{},
		},
		{
			name: "one framework_ one package",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/nuget/one-framework-one-package.v1.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"fixtures/nuget/one-framework-one-package.v1.json"},
				},
			},
		},
		{
			name: "one framework_ two packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/nuget/one-framework-two-packages.v1.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"fixtures/nuget/one-framework-two-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Locations: []string{"fixtures/nuget/one-framework-two-packages.v1.json"},
				},
			},
		},
		{
			name: "two frameworks_ mixed packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/nuget/two-frameworks-mixed-packages.v1.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"fixtures/nuget/two-frameworks-mixed-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Locations: []string{"fixtures/nuget/two-frameworks-mixed-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "2.15.0",
					Locations: []string{"fixtures/nuget/two-frameworks-mixed-packages.v1.json"},
				},
			},
		},
		{
			name: "two frameworks_ different packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/nuget/two-frameworks-different-packages.v1.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"fixtures/nuget/two-frameworks-different-packages.v1.json"},
				},
				{
					Name:      "Test.System",
					Version:   "0.13.0-beta4",
					Locations: []string{"fixtures/nuget/two-frameworks-different-packages.v1.json"},
				},
			},
		},
		{
			name: "two frameworks_ duplicate packages",
			inputConfig: ScanInputMockConfig{
				path: "fixtures/nuget/two-frameworks-duplicate-packages.v1.json",
			},
			wantInventory: []*lockfilescalibr.Inventory{
				{
					Name:      "Test.Core",
					Version:   "6.0.5",
					Locations: []string{"fixtures/nuget/two-frameworks-duplicate-packages.v1.json"},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := lockfilescalibr.NuGetLockExtractor{}
			_, _ = extractionTester(t, e, tt)
		})
	}
}