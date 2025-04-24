package hashextractor

import (
	"context"
	"crypto/sha256"
	"io"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

type Extractor struct {
}

var _ filesystem.Extractor = Extractor{}

func (e Extractor) Name() string { return "ffa/hashextractor" }

func (e Extractor) Version() int { return 0 }

func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	file, err := api.Stat()
	if err != nil {
		return false
	}

	if !file.Mode().IsRegular() {
		return false
	}

	if file.Size() > 1024*1024*50 {
		return false
	}

	return true
}

func (e Extractor) Extract(_ context.Context, fs *filesystem.ScanInput) (inventory.Inventory, error) {
	h := sha256.New()
	_, err := io.Copy(h, fs.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}
	//slog.Info(fmt.Sprintf("Hashing path: %s", fs.Path))
	return inventory.Inventory{
		Packages: []*extractor.Package{
			{
				Name: fs.Path,
				Metadata: &Metadata{
					Hash: h.Sum(nil),
				},
			},
		},
		Findings: nil,
	}, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(_ *extractor.Package) *purl.PackageURL {
	return &purl.PackageURL{
		Type:       "ffa-hash",
		Namespace:  "",
		Name:       "",
		Version:    "",
		Qualifiers: nil,
		Subpath:    "",
	}
}

// Ecosystem returns the OSV ecosystem ('npm') of the software extracted by this extractor.
func (e Extractor) Ecosystem(_ *extractor.Package) string {
	return ""
}

var _ filesystem.Extractor = Extractor{}
