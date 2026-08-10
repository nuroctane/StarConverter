// Package matrix defines the disposable image and crash-test cases used by the StarConverter lab.
package matrix

import (
	"fmt"
	"sort"
)

// Case describes one deterministic image conversion scenario.
type Case struct {
	Name          string
	SourceFS      string
	TargetFS      string
	SectorBytes   int
	ClusterBytes  int
	CapacityMiB   int
	Fragmentation string
	Guarantee     string
}

// Baseline returns the small, fast matrix expected to run in ordinary CI.
func Baseline() []Case {
	filesystems := [][2]string{{"exfat", "ntfs"}, {"ntfs", "exfat"}}
	sectors := []int{512, 4096}
	clusters := []int{4096, 131072}

	cases := make([]Case, 0, len(filesystems)*len(sectors)*len(clusters))
	for _, direction := range filesystems {
		for _, sector := range sectors {
			for _, cluster := range clusters {
				cases = append(cases, Case{
					Name:          fmt.Sprintf("%s-to-%s-s%d-c%d", direction[0], direction[1], sector, cluster),
					SourceFS:      direction[0],
					TargetFS:      direction[1],
					SectorBytes:   sector,
					ClusterBytes:  cluster,
					CapacityMiB:   256,
					Fragmentation: "mixed",
					Guarantee:     "strict",
				})
			}
		}
	}

	sort.Slice(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })
	return cases
}

// Validate rejects malformed matrix entries before any formatter or converter process is launched.
func Validate(test Case) error {
	if test.Name == "" {
		return fmt.Errorf("case name is required")
	}
	if test.SourceFS == test.TargetFS {
		return fmt.Errorf("source and target filesystems must differ")
	}
	if !supportedFS(test.SourceFS) || !supportedFS(test.TargetFS) {
		return fmt.Errorf("unsupported direction %s -> %s", test.SourceFS, test.TargetFS)
	}
	if test.SectorBytes != 512 && test.SectorBytes != 4096 {
		return fmt.Errorf("unsupported logical sector size %d", test.SectorBytes)
	}
	if test.ClusterBytes < test.SectorBytes || !powerOfTwo(test.ClusterBytes) {
		return fmt.Errorf("invalid cluster size %d", test.ClusterBytes)
	}
	if test.CapacityMiB < 64 {
		return fmt.Errorf("capacity must be at least 64 MiB")
	}
	return nil
}

func supportedFS(value string) bool {
	return value == "exfat" || value == "ntfs"
}

func powerOfTwo(value int) bool {
	return value > 0 && value&(value-1) == 0
}
