package assets

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestLocationFinderPrefersEnvAssetDirAndCachesResult(t *testing.T) {
	envDir := t.TempDir()
	externDir := t.TempDir()
	envAsset := filepath.Join(envDir, "geosite.dat")
	externAsset := filepath.Join(externDir, "geosite.dat")
	if err := os.WriteFile(envAsset, []byte("env"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(externAsset, []byte("extern"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DAE_LOCATION_ASSET", envDir)

	finder := NewLocationFinder([]string{externDir})
	got, err := finder.GetLocationAsset(testLogger(), "geosite.dat")
	if err != nil {
		t.Fatal(err)
	}
	if got != envAsset {
		t.Fatalf("GetLocationAsset() = %q, want env asset %q", got, envAsset)
	}

	if err := os.Remove(envAsset); err != nil {
		t.Fatal(err)
	}
	cached, err := finder.GetLocationAsset(testLogger(), "geosite.dat")
	if err != nil {
		t.Fatal(err)
	}
	if cached != envAsset {
		t.Fatalf("cached GetLocationAsset() = %q, want cached env asset %q", cached, envAsset)
	}
}

func TestLocationFinderUsesExternDirWithoutEnvAssetDir(t *testing.T) {
	externDir := t.TempDir()
	externAsset := filepath.Join(externDir, "geoip.dat")
	if err := os.WriteFile(externAsset, []byte("extern"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DAE_LOCATION_ASSET", "")

	finder := NewLocationFinder([]string{externDir})
	got, err := finder.GetLocationAsset(testLogger(), "geoip.dat")
	if err != nil {
		t.Fatal(err)
	}
	if got != externAsset {
		t.Fatalf("GetLocationAsset() = %q, want extern asset %q", got, externAsset)
	}
}

func testLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
}
