package lockfile

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/package-url/packageurl-go"
)

type PoetryLockPackageSource struct {
	Type   string `toml:"type"`
	Commit string `toml:"resolved_reference"`
}

type PoetryLockPackage struct {
	Name     string                  `toml:"name"`
	Version  string                  `toml:"version"`
	Optional bool                    `toml:"optional"`
	Source   PoetryLockPackageSource `toml:"source"`
}

type PoetryLockFile struct {
	Version  int                 `toml:"version"`
	Packages []PoetryLockPackage `toml:"package"`
}

const PoetryEcosystem = PipEcosystem

type PoetryLockExtractor struct{}

// Name of the extractor
func (e PoetryLockExtractor) Name() string { return "python/poetry" }

// Version of the extractor
func (e PoetryLockExtractor) Version() int { return 0 }

func (e PoetryLockExtractor) Requirements() Requirements {
	return Requirements{}
}

func (e PoetryLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "poetry.lock"
}

func (e PoetryLockExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var parsedLockfile *PoetryLockFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*Inventory, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		pkgDetails := &Inventory{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			Locations: []string{input.Path},
			SourceCode: &SourceCodeIdentifier{
				Commit: lockPackage.Source.Commit,
			},
		}
		if lockPackage.Optional {
			pkgDetails.Metadata = DepGroupMetadata{
				DepGroupVals: []string{"optional"},
			}
		} else {
			pkgDetails.Metadata = DepGroupMetadata{
				DepGroupVals: []string{},
			}
		}
		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e PoetryLockExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypePyPi,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e PoetryLockExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e PoetryLockExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case PoetryLockExtractor:
		return string(PoetryEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = PoetryLockExtractor{}
