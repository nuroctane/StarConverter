package crashmodel

import "testing"

func TestCanonicalProtocolIsValid(t *testing.T) {
	t.Parallel()
	if err := Validate(Protocol()); err != nil {
		t.Fatalf("canonical protocol is invalid: %v", err)
	}
}

func TestCampaignCoversEveryApplicableFaultAtEveryBarrier(t *testing.T) {
	t.Parallel()
	campaign, err := Campaign()
	if err != nil {
		t.Fatal(err)
	}
	if len(campaign) != 38 {
		t.Fatalf("expected 38 injections, got %d", len(campaign))
	}
	for _, injection := range campaign {
		if injection.After == Finalized && injection.Recovery != TargetOnly {
			t.Fatalf("finalized injection retained an invalid rollback promise: %+v", injection)
		}
		if injection.After == PrimaryActivated && injection.Recovery != TargetWithEscape {
			t.Fatalf("activation injection lost rollback evidence: %+v", injection)
		}
	}
}

func TestRejectsSkippedReorderedAndWeakenedBarriers(t *testing.T) {
	t.Parallel()

	skipped := Protocol()
	skipped = append(skipped[:4], skipped[5:]...)
	if err := Validate(skipped); err == nil {
		t.Fatal("expected skipped barrier to fail")
	}

	reordered := Protocol()
	reordered[5], reordered[6] = reordered[6], reordered[5]
	if err := Validate(reordered); err == nil {
		t.Fatal("expected backup boot before overlay verification to fail")
	}

	weakened := Protocol()
	weakened[7].Recovery = TargetOnly
	if err := Validate(weakened); err == nil {
		t.Fatal("expected premature rollback release to fail")
	}
}

func TestRejectsDuplicateBarrierAndMissingFlush(t *testing.T) {
	t.Parallel()

	duplicate := Protocol()
	duplicate[4].Barrier = duplicate[3].Barrier
	if err := Validate(duplicate); err == nil {
		t.Fatal("expected duplicate barrier to fail")
	}

	missingFlush := Protocol()
	missingFlush[8].Flush = false
	if err := Validate(missingFlush); err == nil {
		t.Fatal("expected missing durable flush to fail")
	}
}

func TestRecoveryDecisionAccumulatesBeforeImagesAndHonorsFinalizeBoundary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		barrier Barrier
		action  RecoveryAction
	}{
		{RelocationsDone, RestoreStaging},
		{TargetStaged, RestoreStagingAndBackup},
		{OverlayVerified, RestoreStagingAndBackup},
		{BackupBootWritten, RestoreAll},
		{PrimaryActivated, RestoreAll},
		{TargetVerified, RestoreAll},
	}
	for _, test := range cases {
		action, err := Decision(test.barrier, true)
		if err != nil {
			t.Fatalf("decision after %q failed: %v", test.barrier, err)
		}
		if action != test.action {
			t.Fatalf("decision after %q = %q; expected %q", test.barrier, action, test.action)
		}
	}
	if _, err := Decision(Finalized, true); err == nil {
		t.Fatal("finalized transaction incorrectly permitted rollback")
	}
	action, err := Decision(Finalized, false)
	if err != nil || action != AcceptTarget {
		t.Fatalf("finalized target decision = %q, %v", action, err)
	}
}
