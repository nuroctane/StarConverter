// Package crashmodel defines the durable barriers and recovery expectations for
// StarConverter's image-only fault-injection campaign. It does not perform I/O.
package crashmodel

import "fmt"

// Barrier is one acknowledged durable boundary in the conversion protocol.
type Barrier string

const (
	Discovered        Barrier = "discovered"
	CapsuleReserved   Barrier = "capsule-reserved"
	BeforeImagesSaved Barrier = "before-images-saved"
	RelocationsDone   Barrier = "relocations-done"
	TargetStaged      Barrier = "target-staged"
	OverlayVerified   Barrier = "overlay-verified"
	BackupBootWritten Barrier = "backup-boot-written"
	PrimaryActivated  Barrier = "primary-activated"
	TargetVerified    Barrier = "target-verified"
	Finalized         Barrier = "finalized"
)

// RecoveryView is the filesystem view recovery must be able to produce after
// a crash at a durable barrier.
type RecoveryView string

const (
	SourceView       RecoveryView = "source"
	SourceOrTarget   RecoveryView = "source-or-target"
	TargetWithEscape RecoveryView = "target-with-rollback"
	TargetOnly       RecoveryView = "target-only"
)

// Step describes one barrier and the recovery guarantee acknowledged after it.
type Step struct {
	Barrier  Barrier      `json:"barrier"`
	Recovery RecoveryView `json:"recovery"`
	Flush    bool         `json:"flush"`
}

// Protocol returns the canonical transaction ordering. Before activation, the
// source remains authoritative. At and after activation, recovery may validate
// the target or use retained before-images to restore the source. Finalization
// intentionally releases that rollback promise.
func Protocol() []Step {
	return []Step{
		{Discovered, SourceView, false},
		{CapsuleReserved, SourceView, true},
		{BeforeImagesSaved, SourceView, true},
		{RelocationsDone, SourceView, true},
		{TargetStaged, SourceView, true},
		{OverlayVerified, SourceView, true},
		{BackupBootWritten, SourceOrTarget, true},
		{PrimaryActivated, TargetWithEscape, true},
		{TargetVerified, TargetWithEscape, true},
		{Finalized, TargetOnly, true},
	}
}

// RecoveryAction is the modeled deterministic response to a fault at a durable barrier.
type RecoveryAction string

const (
	ReinspectSource         RecoveryAction = "reinspect-source"
	RestoreStaging          RecoveryAction = "restore-staging-before-images"
	RestoreStagingAndBackup RecoveryAction = "restore-staging-and-backup-before-images"
	RestoreAll              RecoveryAction = "restore-all-before-images"
	AcceptTarget            RecoveryAction = "accept-verified-target"
)

// Decision returns the conservative phase-bounded recovery action. It includes
// the next possibly in-flight write group because a crash can occur after bytes
// reach storage but before that group's completion checkpoint is durable.
func Decision(after Barrier, preferRollback bool) (RecoveryAction, error) {
	switch after {
	case Discovered, CapsuleReserved, BeforeImagesSaved:
		return ReinspectSource, nil
	case RelocationsDone:
		return RestoreStaging, nil
	case TargetStaged, OverlayVerified:
		return RestoreStagingAndBackup, nil
	case BackupBootWritten, PrimaryActivated, TargetVerified:
		if preferRollback {
			return RestoreAll, nil
		}
		return AcceptTarget, nil
	case Finalized:
		if preferRollback {
			return "", fmt.Errorf("rollback material was released at %q", after)
		}
		return AcceptTarget, nil
	default:
		return "", fmt.Errorf("unknown recovery barrier %q", after)
	}
}

// Validate checks the ordering and safety promises of a protocol before it is
// used to construct a crash campaign.
func Validate(steps []Step) error {
	canonical := Protocol()
	if len(steps) != len(canonical) {
		return fmt.Errorf("protocol has %d steps; expected %d", len(steps), len(canonical))
	}
	seen := make(map[Barrier]struct{}, len(steps))
	for index, step := range steps {
		if step.Barrier == "" {
			return fmt.Errorf("step %d has no barrier", index)
		}
		if _, exists := seen[step.Barrier]; exists {
			return fmt.Errorf("barrier %q is duplicated", step.Barrier)
		}
		seen[step.Barrier] = struct{}{}
		expected := canonical[index]
		if step.Barrier != expected.Barrier {
			return fmt.Errorf("step %d is %q; expected %q", index, step.Barrier, expected.Barrier)
		}
		if step.Recovery != expected.Recovery {
			return fmt.Errorf("barrier %q promises %q; expected %q", step.Barrier, step.Recovery, expected.Recovery)
		}
		if step.Flush != expected.Flush {
			return fmt.Errorf("barrier %q has flush=%t; expected %t", step.Barrier, step.Flush, expected.Flush)
		}
	}
	return nil
}

// Fault is an injected failure immediately after a durable barrier.
type Fault string

const (
	ProcessTermination Fault = "process-termination"
	TornNextWrite      Fault = "torn-next-write"
	StaleRead          Fault = "stale-read"
	ReorderedWrite     Fault = "reordered-write"
)

// Injection is one deterministic campaign entry.
type Injection struct {
	After    Barrier      `json:"after"`
	Fault    Fault        `json:"fault"`
	Recovery RecoveryView `json:"recovery"`
}

// Campaign expands every durable protocol barrier across the supported fault
// models. The discovery step has no completed write to tear or reorder, so only
// process termination and stale-read behavior apply there.
func Campaign() ([]Injection, error) {
	steps := Protocol()
	if err := Validate(steps); err != nil {
		return nil, err
	}
	faults := []Fault{ProcessTermination, TornNextWrite, StaleRead, ReorderedWrite}
	result := make([]Injection, 0, len(steps)*len(faults))
	for _, step := range steps {
		for _, fault := range faults {
			if step.Barrier == Discovered && (fault == TornNextWrite || fault == ReorderedWrite) {
				continue
			}
			result = append(result, Injection{step.Barrier, fault, step.Recovery})
		}
	}
	return result, nil
}
