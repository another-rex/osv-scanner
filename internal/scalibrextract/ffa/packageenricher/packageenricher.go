package packageenricher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"strings"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/ecosystemmock"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/ffa/hashextractor"
	"golang.org/x/sync/errgroup"
)

const Name = "ffa/packageenricher"

type PackageEnricher struct {
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	slog.Info(fmt.Sprintf("%s elapsed %s", name, elapsed))
}

func (p PackageEnricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	start := time.Now()
	timeTrack(start, "Begin hash matching")
	g, groupctx := errgroup.WithContext(ctx)
	g.SetLimit(200)

	db, err := spanner.NewClient(groupctx, "projects/sos-josieang/instances/home-oregon-test/databases/home-oregon-test")
	if err != nil {
		return err
	}

	ch := make(chan PackageMatch)
	chAllPkgMatches := make(chan map[string]PackageMatch)

	newPackages := make([]*extractor.Package, 0, len(inv.Packages))

	go func() {
		pkgMatches := map[string]PackageMatch{}

		for pkg := range ch {
			if pkgMatch, ok := pkgMatches[pkg.PkgName]; ok {
				pkgMatch.Intersection(pkg)
			} else {
				pkgMatches[pkg.PkgName] = pkg
			}
		}

		chAllPkgMatches <- pkgMatches
	}()

	for _, pkg := range inv.Packages {
		if pkg.Extractor.Name() != "ffa/hashextractor" {
			newPackages = append(newPackages, pkg)
			continue
		}

		g.Go(func() error {
			hash := pkg.Metadata.(*hashextractor.Metadata).Hash
			st := spanner.NewStatement(`
				SELECT DiscriminantHashesTest.Key, DiscriminantHashesTest.ArtifactHash FROM DiscriminantHashesTest
				WHERE SHA256Sum=(@Hash)
				`)
			st.Params["Hash"] = hash

			pkgMatch := PackageMatch{
				VersionIntersection: map[string]ArtifactHash{},
				Files:               map[string]map[string]struct{}{},
			}
			iter := db.Single().QueryWithOptions(groupctx, st, spanner.QueryOptions{RequestTag: "origin=rexpan-ffa"})
			err := iter.Do(func(row *spanner.Row) error {
				var keyRaw string
				var artifactHash ArtifactHash
				err := row.ColumnByName("Key", &keyRaw)
				if err != nil {
					return err
				}

				err = row.ColumnByName("ArtifactHash", &artifactHash)
				if err != nil {
					return err
				}

				key, err := parseSpannerKey(keyRaw)
				if err != nil {
					return err
				}

				pkgMatch.PkgName = key["apt.p"]
				pkgMatch.VersionIntersection[key["apt.v"]] = artifactHash
				if pkgMatch.Files[pkg.Name] == nil {
					pkgMatch.Files[pkg.Name] = map[string]struct{}{}
				}
				pkgMatch.Files[pkg.Name][key["apt.v"]] = struct{}{}

				return nil
			})

			if err != nil {
				return err
			}

			ch <- pkgMatch

			return nil
		})
	}

	err = g.Wait()
	if err != nil {
		return err
	}

	close(ch)
	pkgMatches := <-chAllPkgMatches
	timeTrack(start, "Got all hash matches & intersected")

	statusPkgs := map[string]string{}
	correctMatches := 0
	for _, e := range inv.Packages {
		if e.Extractor.Name() != "os/dpkg" {
			continue
		}
		statusPkgs[e.Name] = e.Version

		if matches, ok := pkgMatches[e.Name]; ok {
			versionCount := len(matches.VersionIntersection)
			if versionCount == 1 {
				// Compare version matches
				for version := range matches.VersionIntersection {
					if version != e.Version {
						slog.Info(fmt.Sprintf("Package %q has different version in (status file vs hash match): %s vs %s", e.Name, e.Version, version))
					} else {
						correctMatches += 1
					}
				}
			} else if versionCount == 0 {
				slog.Info(fmt.Sprintf("Package %q has no version in hash match: %s", e.Name, e.Version))
			} else {
				for version := range matches.VersionIntersection {
					slog.Info(fmt.Sprintf("Package %q has multiple versions: %s vs %s", e.Name, e.Version, version))
				}
			}
		} else {
			slog.Info(fmt.Sprintf("Package %q is in status file, but not in hash match", e.Name))
		}
	}

	g, groupctx = errgroup.WithContext(ctx)
	g.SetLimit(200)

	db, err = spanner.NewClient(groupctx, "projects/sos-scratch/instances/home-oregon/databases/sos-prod")
	if err != nil {
		return err
	}

	chOutputPackages := make(chan *extractor.Package)
	chReturnResult := make(chan []*extractor.Package)

	go func() {
		for pkg := range chOutputPackages {
			newPackages = append(newPackages, pkg)
		}

		chReturnResult <- newPackages
	}()

	for pkgName, pkgMatch := range pkgMatches {
		if _, ok := statusPkgs[pkgName]; ok {
			continue
		}
		// TODO: If there is more than 1, we should also query
		if len(pkgMatch.VersionIntersection) != 1 {
			continue
		}

		g.Go(func() error {
			var outputPkg *extractor.Package

			for ver, pkgHash := range pkgMatch.VersionIntersection {
				outputPkg, err = loadPackageDetails(groupctx, db, pkgName, ver, pkgHash)
				if err != nil {
					return err
				}
			}

			outputPkg.Locations = []string{"FullFilesystemAccountability"}
			for path, versions := range pkgMatch.Files {
				if _, found := versions[outputPkg.Version]; !found {
					continue
				}
				outputPkg.Locations = append(outputPkg.Locations, path)
			}

			chOutputPackages <- outputPkg

			return nil
		})
		//slog.Info(fmt.Sprintf("Package %q is in hash match, but not in status file", pkgName))
	}

	err = g.Wait()
	if err != nil {
		return err
	}

	close(chOutputPackages)

	timeTrack(start, "Complete enrichment")

	//slog.Info(fmt.Sprintf("%d packages matched", correctMatches))

	inv.Packages = <-chReturnResult

	return nil
}

func loadPackageDetails(ctx context.Context, db *spanner.Client, pkgName, version string, pkgHash []byte) (*extractor.Package, error) {
	st := spanner.NewStatement(`
					SELECT Value FROM AptBinaryPackagesExo WHERE SHA256=(@Hash)
				`)
	st.Params["Hash"] = pkgHash
	iter := db.Single().QueryWithOptions(ctx, st, spanner.QueryOptions{RequestTag: "origin=rexpan-ffa"})

	row, err := iter.Next()
	if err != nil {
		slog.Error(err.Error())
		return nil, err
	}
	var valueInJSON spanner.NullJSON
	err = row.ColumnByName("Value", &valueInJSON)
	if err != nil {
		slog.Error(err.Error())
		return nil, err
	}
	if !valueInJSON.Valid {
		return nil, errors.New("invalid JSON")
	}

	val, err := valueInJSON.MarshalJSON()
	if err != nil {
		slog.Error(err.Error())
		return nil, err
	}

	var actualValue BinaryPackage
	err = json.Unmarshal(val, &actualValue)
	if err != nil {
		slog.Error(err.Error())
		return nil, err
	}

	var sourceName, sourceVersion string
	controlInner := actualValue.Data.Control.Control
	if controlInner.Source != nil {
		if controlInner.Source.Package != "" {
			sourceName = controlInner.Source.Package
		}

		if controlInner.Source.Version != "" {
			sourceVersion = controlInner.Source.Version
		}

	}

	return &extractor.Package{
		Name:    pkgName,
		Version: version,
		Extractor: ecosystemmock.Extractor{
			MockEcosystem: "Debian:12",
		},
		// TODO: Fully fillout metadata
		Metadata: &dpkg.Metadata{
			PackageName:       pkgName,
			Status:            "",
			SourceName:        sourceName,
			SourceVersion:     sourceVersion,
			PackageVersion:    version,
			OSID:              "Debian:12",
			OSVersionCodename: "",
			OSVersionID:       "Debian:12",
			Maintainer:        "",
			Architecture:      "amd64",
		},
	}, nil
}

type ArtifactHash []byte

type PackageMatch struct {
	PkgName string
	// The intersection of all versions listed in DiscriminantBlobMatches for
	// this package.
	VersionIntersection map[string]ArtifactHash

	// The files that were unique to the Pk.
	// Filename -> version
	Files map[string]map[string]struct{}
}

func (pm *PackageMatch) Intersection(other PackageMatch) {
	if other.PkgName != pm.PkgName {
		slog.Error("Package names do not match, skipping")
		return
	}

	for s := range other.VersionIntersection {
		if _, ok := pm.VersionIntersection[s]; ok {
			continue
		}
		delete(pm.VersionIntersection, s)
	}
	var toDelete []string
	for s := range pm.VersionIntersection {
		if _, ok := other.VersionIntersection[s]; ok {
			continue
		}
		toDelete = append(toDelete, s)
	}
	for _, d := range toDelete {
		delete(pm.VersionIntersection, d)
	}

	for filename := range other.Files {
		if pm.Files[filename] == nil {
			pm.Files[filename] = map[string]struct{}{}
		}
		maps.Copy(pm.Files[filename], other.Files[filename])
	}
}

// Sample string: "apt.r=http%3A%2F%2Fdeb.debian.org%2Fdebian-security!apt.p=glibc-source!apt.v=2.31-13%2Bdeb11u10!apt.a=arm64!apt.d=bullseye-security!apt.c=main"
func parseSpannerKey(key string) (map[string]string, error) {
	resultMap := map[string]string{}
	// Split the input string by the '!' delimiter to get individual pairs
	pairs := strings.Split(key, "!")

	for _, pair := range pairs {
		if pair == "" {
			continue // Skip empty segments if any
		}

		// Split each pair by the first '=' delimiter into key and value
		// Using SplitN ensures that any '=' within the value itself is preserved
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid pair format: %q", pair)
		}

		key := parts[0]
		encodedValue := parts[1]

		if key == "" {
			return nil, fmt.Errorf("empty key found in pair: %q", pair)
		}

		// URL-decode the value part
		decodedValue, err := url.QueryUnescape(encodedValue)
		if err != nil {
			return nil, fmt.Errorf("failed to decode value for key %q: %w", key, err)
		}

		// Add the key and decoded value to the map
		resultMap[key] = decodedValue
	}

	return resultMap, nil
}

func (p PackageEnricher) Name() string {
	return Name
}

func (p PackageEnricher) Version() int {
	return 0
}

func (p PackageEnricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network: plugin.NetworkOnline,
	}
}

func (p PackageEnricher) RequiredExtractors() []string {
	return []string{"ffa/hashextractor"}
}
