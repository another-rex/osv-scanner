package pomxml_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/lockfilescalibr/extractor"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/pomxml"
	"github.com/google/osv-scanner/internal/lockfilescalibr/othermetadata"
	"github.com/google/osv-scanner/internal/lockfilescalibr/sharedtesthelpers"
)

func TestExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputConfig sharedtesthelpers.ScanInputMockConfig
		want        bool
	}{
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "pom.xml",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/pom.xml",
			},
			want: true,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/pom.xml/file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path/to/my/pom.xml.file",
			},
			want: false,
		},
		{
			name: "",
			inputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "path.to.my.pom.xml",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := pomxml.Extractor{}
			got := e.FileRequired(tt.inputConfig.Path, sharedtesthelpers.GenerateFileInfoMock(t, tt.inputConfig))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputConfig.Path, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []sharedtesthelpers.TestTableEntry{
		{
			Name: "invalid",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/not-pom.txt",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "invalid syntax",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/invalid-syntax.xml",
			},
			WantErrContaining: "could not extract from",
		},
		{
			Name: "no packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/empty.xml",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/one-package.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.apache.maven:maven-artifact",
					Version:   "1.0.0",
					Locations: []string{"testdata/one-package.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/two-packages.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "io.netty:netty-all",
					Version:   "4.1.42.Final",
					Locations: []string{"testdata/two-packages.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.slf4j:slf4j-log4j12",
					Version:   "1.7.25",
					Locations: []string{"testdata/two-packages.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "with dependency management",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/with-dependency-management.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "io.netty:netty-all",
					Version:   "4.1.9",
					Locations: []string{"testdata/with-dependency-management.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.slf4j:slf4j-log4j12",
					Version:   "1.7.25",
					Locations: []string{"testdata/with-dependency-management.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "com.google.code.findbugs:jsr305",
					Version:   "3.0.2",
					Locations: []string{"testdata/with-dependency-management.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "interpolation",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/interpolation.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.mine:mypackage",
					Version:   "1.0.0",
					Locations: []string{"testdata/interpolation.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.mine:my.package",
					Version:   "2.3.4",
					Locations: []string{"testdata/interpolation.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.mine:ranged-package",
					Version:   "9.4.35.v20201120",
					Locations: []string{"testdata/interpolation.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "with scope",
			InputConfig: sharedtesthelpers.ScanInputMockConfig{
				Path: "testdata/with-scope.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "abc:xyz",
					Version:   "1.2.3",
					Locations: []string{"testdata/with-scope.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "junit:junit",
					Version:   "4.12",
					Locations: []string{"testdata/with-scope.xml"},
					Metadata: othermetadata.DepGroupMetadata{
						DepGroupVals: []string{"test"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()
			e := pomxml.Extractor{}
			_, _ = sharedtesthelpers.ExtractionTester(t, e, tt)
		})
	}
}