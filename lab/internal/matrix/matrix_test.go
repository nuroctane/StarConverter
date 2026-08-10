package matrix

import "testing"

func TestBaselineIsValid(t *testing.T) {
	t.Parallel()

	cases := Baseline()
	if len(cases) != 8 {
		t.Fatalf("expected 8 baseline cases, got %d", len(cases))
	}
	for _, test := range cases {
		if err := Validate(test); err != nil {
			t.Errorf("case %q is invalid: %v", test.Name, err)
		}
	}
}

func TestRejectsSameFilesystem(t *testing.T) {
	t.Parallel()

	test := Baseline()[0]
	test.TargetFS = test.SourceFS
	if err := Validate(test); err == nil {
		t.Fatal("expected same-filesystem case to be rejected")
	}
}

func TestRejectsUnsupportedSector(t *testing.T) {
	t.Parallel()

	test := Baseline()[0]
	test.SectorBytes = 2048
	if err := Validate(test); err == nil {
		t.Fatal("expected unsupported sector size to be rejected")
	}
}
