use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use eframe::egui::{
    self, Align, Button, Color32, FontId, Frame, Label, Layout, Margin, RichText, Stroke,
    TextStyle, Vec2,
};
use starconverter_core::candidate_export::{
    CandidateExportEvidence, CandidateExportLimits, CandidateVerificationEvidence,
    CandidateVerificationLimits, export_candidate_image, verify_bound_export,
};
use starconverter_core::cross_format::{
    ExfatToNtfsLimits, ExfatToNtfsOptions, NtfsToExfatLimits, NtfsToExfatOptions,
    plan_lossless_exfat_to_ntfs, plan_lossless_ntfs_to_exfat,
};
use starconverter_core::geometry::{DestinationReservation, SourceAllocation};
use starconverter_core::image::ImageFile;
use starconverter_core::inspect::{inspect_image, inspect_open_image};
use starconverter_core::object::ObjectGraph;
use starconverter_core::phase::{
    PhaseWritePreview, preview_exfat_phase_writes, preview_ntfs_phase_writes,
};
use starconverter_core::preimage::PreimageLimits;
use starconverter_core::preservation::PreservationReport;
use starconverter_core::{
    ConversionPlan, FileSystem, GuaranteeMode, HealthState, Planner, SemanticFeature, Severity,
    VolumeProfile,
};

const VOID: Color32 = Color32::from_rgb(5, 5, 6);
const SURFACE: Color32 = Color32::from_rgb(10, 11, 12);
const RAISED: Color32 = Color32::from_rgb(17, 19, 21);
const LINE: Color32 = Color32::from_rgb(41, 45, 50);
const LINE_STRONG: Color32 = Color32::from_rgb(89, 97, 107);
const INK: Color32 = Color32::from_rgb(242, 244, 245);
const MUTED: Color32 = Color32::from_rgb(154, 161, 170);
const FAINT: Color32 = Color32::from_rgb(98, 105, 113);
const READY: Color32 = Color32::from_rgb(123, 255, 178);
const WARNING: Color32 = Color32::from_rgb(255, 200, 87);
const DANGER: Color32 = Color32::from_rgb(255, 96, 119);
const WORKING: Color32 = Color32::from_rgb(168, 216, 255);

const ASCII_MARK: &str = r"+---------------------------------------+
| STAR :: CONVERTER                     |
| EXFAT <-> NTFS / ANALYZE BEFORE WRITE |
+---------------------------------------+";

const INTERRUPTED_EXPORT_GUIDANCE: &str = "[RECOVERY] Never rename or use a .starconverter-partial-* file.\n\
[RECOVERY] If both final candidate and escrow exist, verify them here before mounting or copying data.\n\
[RECOVERY] If only partial or escrow artifacts remain, confirm no export is running, preserve them if forensic review matters, then rerun to a new output name.\n\
[SAFE] The original source was opened read-only; this screen cannot repair or activate a filesystem.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobKind {
    Inspect,
    Preview,
    Export,
    VerifyExport,
}

impl JobKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Inspect => "image inspection",
            Self::Preview => "exact preview",
            Self::Export => "candidate export",
            Self::VerifyExport => "export verification",
        }
    }
}

#[derive(Debug)]
struct InspectionJobSuccess {
    profile: VolumeProfile,
}

#[derive(Debug)]
struct PreviewJobSuccess {
    profile: VolumeProfile,
    target: FileSystem,
    report: String,
}

#[derive(Debug)]
struct ExportJobSuccess {
    profile: VolumeProfile,
    target: FileSystem,
    source_path: String,
    evidence: CandidateExportEvidence,
}

#[derive(Debug)]
enum JobOutcome {
    Inspection(InspectionJobSuccess),
    Preview(PreviewJobSuccess),
    Export(ExportJobSuccess),
    Verification(CandidateVerificationEvidence),
    Failed { kind: JobKind, message: String },
}

#[derive(Debug)]
struct JobMessage {
    id: u64,
    outcome: JobOutcome,
}

#[derive(Debug)]
struct ActiveJob {
    id: u64,
    kind: JobKind,
    cancelled: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobResultDisposition {
    Apply,
    IgnoreStale,
}

fn job_result_disposition(active: Option<&ActiveJob>, message_id: u64) -> JobResultDisposition {
    match active {
        Some(job) if job.id == message_id && !job.cancelled.load(Ordering::Acquire) => {
            JobResultDisposition::Apply
        }
        Some(_) | None => JobResultDisposition::IgnoreStale,
    }
}

#[derive(Debug)]
struct BackgroundJobs {
    sender: mpsc::Sender<JobMessage>,
    receiver: mpsc::Receiver<JobMessage>,
    next_id: u64,
    active: Option<ActiveJob>,
}

impl BackgroundJobs {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            sender,
            receiver,
            next_id: 1,
            active: None,
        }
    }

    const fn active(&self) -> Option<&ActiveJob> {
        self.active.as_ref()
    }

    const fn is_busy(&self) -> bool {
        self.active.is_some()
    }

    fn start<F>(&mut self, kind: JobKind, work: F) -> Result<u64, String>
    where
        F: FnOnce() -> JobOutcome + Send + 'static,
    {
        if self.is_busy() {
            return Err("another background job is already active".into());
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let sender = self.sender.clone();
        thread::Builder::new()
            .name(format!(
                "starconverter-{}-{id}",
                kind.label().replace(' ', "-")
            ))
            .spawn(move || {
                if worker_cancelled.load(Ordering::Acquire) {
                    return;
                }
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                    .unwrap_or_else(|_| JobOutcome::Failed {
                        kind,
                        message: "background worker panicked; no result was accepted".into(),
                    });
                let _ = sender.send(JobMessage { id, outcome });
            })
            .map_err(|error| format!("could not start {} worker: {error}", kind.label()))?;
        self.active = Some(ActiveJob {
            id,
            kind,
            cancelled,
        });
        Ok(id)
    }

    fn cancel(&mut self) -> Option<JobKind> {
        let active = self.active.take()?;
        active.cancelled.store(true, Ordering::Release);
        Some(active.kind)
    }

    fn take_ready(&mut self) -> Option<JobOutcome> {
        loop {
            let message = self.receiver.try_recv().ok()?;
            if job_result_disposition(self.active.as_ref(), message.id)
                == JobResultDisposition::Apply
            {
                self.active = None;
                return Some(message.outcome);
            }
        }
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(Vec2::new(1180.0, 760.0))
            .with_min_inner_size(Vec2::new(760.0, 580.0)),
        ..Default::default()
    };

    eframe::run_native(
        "StarConverter",
        options,
        Box::new(|creation_context| Ok(Box::new(StarConverterApp::new(creation_context)))),
    )
}

#[derive(Debug)]
struct StarConverterApp {
    source: VolumeProfile,
    target: FileSystem,
    mode: GuaranteeMode,
    plan: ConversionPlan,
    image_path: String,
    real_source: bool,
    inspection_status: String,
    exact_preview: Option<String>,
    verification_candidate_path: String,
    verification_escrow_path: String,
    verification_source_path: String,
    verification_status: String,
    verification_report: Option<String>,
    verification_ok: bool,
    jobs: BackgroundJobs,
    activity: Vec<String>,
}

impl StarConverterApp {
    fn new(context: &eframe::CreationContext<'_>) -> Self {
        configure_style(&context.egui_ctx);
        let source = VolumeProfile::demo_exfat();
        let target = FileSystem::Ntfs;
        let mode = GuaranteeMode::Strict;
        let plan = Planner.plan(&source, target, mode);
        Self {
            source,
            target,
            mode,
            plan,
            image_path: String::new(),
            real_source: false,
            inspection_status: "Enter a regular image path to begin read-only analysis.".into(),
            exact_preview: None,
            verification_candidate_path: String::new(),
            verification_escrow_path: String::new(),
            verification_source_path: String::new(),
            verification_status:
                "Select a final candidate and its escrow sidecar for read-only verification.".into(),
            verification_report: None,
            verification_ok: false,
            jobs: BackgroundJobs::new(),
            activity: vec![
                "00:00:00  [READY] UI initialized".into(),
                "00:00:00  [SAFE]  raw-device backend absent".into(),
                "00:00:00  [LOCKED] serializer activation gaps remain".into(),
                "00:00:00  [INFO]  synthetic demo source selected".into(),
            ],
        }
    }

    fn replan(&mut self) {
        self.plan = Planner.plan(&self.source, self.target, self.mode);
    }

    fn start_background_job<F>(&mut self, kind: JobKind, work: F)
    where
        F: FnOnce() -> JobOutcome + Send + 'static,
    {
        match self.jobs.start(kind, work) {
            Ok(id) => self.activity.push(format!(
                "00:00:00  [WORKING] {} started :: job {id}",
                kind.label()
            )),
            Err(message) => self.apply_job_outcome(JobOutcome::Failed { kind, message }),
        }
    }

    fn poll_background_jobs(&mut self) {
        while let Some(outcome) = self.jobs.take_ready() {
            self.apply_job_outcome(outcome);
        }
    }

    fn cancel_background_job(&mut self) {
        let Some(kind) = self.jobs.cancel() else {
            return;
        };
        let message = format!(
            "{} result detached; an already-running worker may finish safely in the background",
            kind.label()
        );
        self.activity
            .push(format!("00:00:00  [DETACHED] {message}"));
        match kind {
            JobKind::VerifyExport => {
                self.verification_ok = false;
                self.verification_report = None;
                self.verification_status = format!("Cancelled: {message}.");
            }
            JobKind::Inspect | JobKind::Preview | JobKind::Export => {
                self.inspection_status = format!("Cancelled: {message}.");
            }
        }
    }

    fn apply_job_outcome(&mut self, outcome: JobOutcome) {
        match outcome {
            JobOutcome::Inspection(success) => {
                let inventory_status = if success.profile.inventory_complete {
                    "complete bounded inventory normalized"
                } else {
                    "inventory incomplete; conversion remains blocked"
                };
                self.target = opposite_filesystem(success.profile.filesystem);
                self.source = success.profile;
                self.real_source = true;
                self.inspection_status = format!(
                    "Read-only evidence accepted: {} boot/allocation integrity; {inventory_status}.",
                    self.source.filesystem,
                );
                self.activity.push(format!(
                    "00:00:00  [READY] read-only image evidence :: {}",
                    self.source.display_name
                ));
                self.replan();
            }
            JobOutcome::Preview(success) => {
                self.source = success.profile;
                self.target = success.target;
                self.real_source = true;
                self.exact_preview = Some(success.report);
                self.inspection_status =
                    "Exact candidate and rollback before-images captured in memory; no writes performed."
                        .into();
                self.activity
                    .push("00:00:00  [SAFE]  exact read-only transaction preview ready".into());
                self.replan();
            }
            JobOutcome::Export(success) => {
                self.source = success.profile;
                self.target = success.target;
                self.real_source = true;
                let evidence = success.evidence;
                self.verification_candidate_path = evidence.output_path.display().to_string();
                self.verification_escrow_path = evidence
                    .escrow_path
                    .as_ref()
                    .map_or_else(String::new, |path| path.display().to_string());
                self.verification_source_path = success.source_path;
                self.verification_status = if evidence.escrow_path.is_some() {
                    "Export complete. Run read-only verification below before using the candidate."
                        .into()
                } else {
                    "Strict export complete without an escrow sidecar.".into()
                };
                self.verification_report = None;
                self.verification_ok = false;
                self.exact_preview = Some(export_evidence_report(&evidence));
                self.inspection_status =
                    "New target image exported and independently reinspected; source hash unchanged."
                        .into();
                self.activity.push(format!(
                    "00:00:00  [COMPLETE] copy-based {} image :: {}",
                    evidence.target_filesystem,
                    evidence.output_path.display()
                ));
                self.replan();
            }
            JobOutcome::Verification(evidence) => {
                self.verification_ok = true;
                self.verification_status =
                    "Candidate and bound escrow passed every read-only check.".into();
                self.verification_report = Some(verification_evidence_report(&evidence));
                self.activity.push(format!(
                    "00:00:00  [VERIFIED] bound {} candidate :: {}",
                    evidence.target_filesystem,
                    evidence.candidate_path.display()
                ));
            }
            JobOutcome::Failed { kind, message } => {
                self.activity.push(format!(
                    "00:00:00  [BLOCKED] {} failed :: {message}",
                    kind.label()
                ));
                match kind {
                    JobKind::VerifyExport => {
                        self.verification_ok = false;
                        self.verification_status = format!("Verification failed: {message}");
                        self.verification_report = Some(verification_failure_report(&message));
                    }
                    JobKind::Inspect => {
                        self.real_source = false;
                        self.inspection_status = message;
                    }
                    JobKind::Preview => {
                        self.exact_preview = None;
                        self.inspection_status = message;
                    }
                    JobKind::Export => self.inspection_status = message,
                }
            }
        }
    }

    fn select_exfat_demo(&mut self) {
        self.source = VolumeProfile::demo_exfat();
        self.target = FileSystem::Ntfs;
        self.real_source = false;
        self.exact_preview = None;
        self.inspection_status = "Synthetic exFAT capability profile selected.".into();
        self.replan();
    }

    fn select_ntfs_demo(&mut self) {
        let mut source = VolumeProfile::demo_exfat();
        source.display_name = "DEMO_WORKSPACE".into();
        source.stable_id = "image://demo-workspace.ntfs".into();
        source.filesystem = FileSystem::Ntfs;
        source.features = vec![
            SemanticFeature::AccessControl,
            SemanticFeature::AlternateDataStreams,
            SemanticFeature::SparseFiles,
        ];
        self.source = source;
        self.target = FileSystem::ExFat;
        self.real_source = false;
        self.exact_preview = None;
        self.inspection_status = "Synthetic NTFS capability profile selected.".into();
        self.replan();
    }

    fn analyze_image(&mut self) {
        self.exact_preview = None;
        let path = self.image_path.trim().to_owned();
        if path.is_empty() {
            self.inspection_status = "Image path is required.".into();
            self.activity
                .push("00:00:00  [BLOCKED] image path is empty".into());
            return;
        }
        self.inspection_status = "Read-only image inspection is running in the background.".into();
        self.start_background_job(JobKind::Inspect, move || match inspect_image(&path) {
            Ok(inspection) => JobOutcome::Inspection(InspectionJobSuccess {
                profile: inspection.profile,
            }),
            Err(error) => JobOutcome::Failed {
                kind: JobKind::Inspect,
                message: error.to_string(),
            },
        });
    }

    fn choose_image(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Select a regular exFAT or NTFS image")
            .pick_file()
        else {
            return;
        };
        self.image_path = path.display().to_string();
        self.real_source = false;
        self.exact_preview = None;
        self.inspection_status = "Image selected; analysis has not started.".into();
        self.activity
            .push("00:00:00  [READY] regular image path selected".into());
    }

    fn save_plan(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save StarConverter analysis plan")
            .set_file_name("starconverter-plan.txt")
            .add_filter("Text report", &["txt"])
            .save_file()
        else {
            return;
        };
        let mut report = plan_report(&self.plan);
        if let Some(preview) = &self.exact_preview {
            report.push('\n');
            report.push_str(preview);
        }
        match fs::write(&path, report) {
            Ok(()) => self.activity.push(format!(
                "00:00:00  [SAVED] plan report :: {}",
                path.display()
            )),
            Err(error) => self.activity.push(format!(
                "00:00:00  [BLOCKED] could not save plan :: {error}"
            )),
        }
    }

    fn preview_image(&mut self) {
        let source_path = self.image_path.trim().to_owned();
        if source_path.is_empty() {
            self.inspection_status = "Image path is required.".into();
            self.activity
                .push("00:00:00  [BLOCKED] preview path is empty".into());
            return;
        }
        let mode = self.mode;
        self.exact_preview = None;
        self.inspection_status = "Exact preview is being built in the background.".into();
        self.start_background_job(JobKind::Preview, move || {
            match build_exact_preview(&source_path, mode) {
                Ok(success) => JobOutcome::Preview(success),
                Err(message) => JobOutcome::Failed {
                    kind: JobKind::Preview,
                    message,
                },
            }
        });
    }

    fn export_new_image(&mut self) {
        let source_path = self.image_path.trim().to_owned();
        if source_path.is_empty() {
            self.inspection_status = "Image path is required.".into();
            self.activity
                .push("00:00:00  [BLOCKED] export source path is empty".into());
            return;
        }
        let Some(output_path) = rfd::FileDialog::new()
            .set_title("Create a new converted image (existing paths are refused)")
            .set_file_name("starconverter-output.img")
            .add_filter("Filesystem image", &["img"])
            .save_file()
        else {
            return;
        };

        let mode = self.mode;
        self.inspection_status = "Create-new candidate export is running in the background.".into();
        self.start_background_job(JobKind::Export, move || {
            match build_candidate_export(&source_path, &output_path, mode) {
                Ok(success) => JobOutcome::Export(success),
                Err(message) => JobOutcome::Failed {
                    kind: JobKind::Export,
                    message,
                },
            }
        });
    }

    fn choose_verification_candidate(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Select the final candidate image to verify read-only")
            .pick_file()
        {
            self.verification_candidate_path = path.display().to_string();
            self.clear_verification_result("Candidate selected; verification has not run.");
        }
    }

    fn choose_verification_escrow(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Select the candidate-bound StarConverter escrow sidecar")
            .pick_file()
        {
            self.verification_escrow_path = path.display().to_string();
            self.clear_verification_result("Escrow selected; verification has not run.");
        }
    }

    fn choose_verification_source(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Optionally select the original source image for identity verification")
            .pick_file()
        {
            self.verification_source_path = path.display().to_string();
            self.clear_verification_result("Original source selected; verification has not run.");
        }
    }

    fn clear_verification_result(&mut self, status: &str) {
        self.verification_status = status.into();
        self.verification_report = None;
        self.verification_ok = false;
    }

    fn verify_export_read_only(&mut self) {
        let candidate = self.verification_candidate_path.trim().to_owned();
        let escrow = self.verification_escrow_path.trim().to_owned();
        if let Some(missing) = missing_verification_path(&candidate, &escrow) {
            self.verification_ok = false;
            self.verification_status = missing.into();
            self.verification_report = Some(verification_failure_report(missing));
            self.activity.push(format!(
                "00:00:00  [BLOCKED] export verification :: {missing}"
            ));
            return;
        }
        let source = self.verification_source_path.trim().to_owned();
        self.verification_ok = false;
        self.verification_report = None;
        self.verification_status = "Read-only bound export verification is running.".into();
        self.start_background_job(JobKind::VerifyExport, move || {
            let source = (!source.is_empty()).then(|| PathBuf::from(source));
            match verify_bound_export(
                &candidate,
                &escrow,
                source.as_deref(),
                CandidateVerificationLimits::default(),
            ) {
                Ok(evidence) => JobOutcome::Verification(evidence),
                Err(error) => JobOutcome::Failed {
                    kind: JobKind::VerifyExport,
                    message: error.to_string(),
                },
            }
        });
    }
}

const fn opposite_filesystem(filesystem: FileSystem) -> FileSystem {
    match filesystem {
        FileSystem::ExFat => FileSystem::Ntfs,
        FileSystem::Ntfs => FileSystem::ExFat,
        FileSystem::Unknown => FileSystem::Unknown,
    }
}

fn build_exact_preview(
    source_path: &str,
    mode: GuaranteeMode,
) -> Result<PreviewJobSuccess, String> {
    let image = ImageFile::open(source_path).map_err(|error| error.to_string())?;
    let inspection = inspect_open_image(&image).map_err(|error| error.to_string())?;
    let target = opposite_filesystem(inspection.profile.filesystem);
    if target == FileSystem::Unknown {
        return Err("recognized image has unknown filesystem".into());
    }
    let report = match (
        inspection.normalized_exfat.as_deref(),
        inspection.normalized_ntfs.as_deref(),
        target,
    ) {
        (Some(normalized), None, FileSystem::Ntfs) => {
            let plan = plan_lossless_exfat_to_ntfs(
                normalized,
                mode,
                ExfatToNtfsOptions::default(),
                ExfatToNtfsLimits::default(),
            )
            .map_err(|error| format!("cross-format plan refused: {error}"))?;
            let preview =
                preview_ntfs_phase_writes(&image, &plan.destination, PreimageLimits::default())
                    .map_err(|error| format!("phase preview failed: {error}"))?;
            exact_preview_report(
                &preview,
                &plan.destination.reservations,
                &plan.destination.source_allocations,
                &plan.preservation,
            )
        }
        (None, Some(normalized), FileSystem::ExFat) => {
            let plan = plan_lossless_ntfs_to_exfat(
                normalized,
                mode,
                NtfsToExfatOptions::default(),
                NtfsToExfatLimits::default(),
            )
            .map_err(|error| format!("cross-format plan refused: {error}"))?;
            let preview =
                preview_exfat_phase_writes(&image, &plan.destination, PreimageLimits::default())
                    .map_err(|error| format!("phase preview failed: {error}"))?;
            exact_preview_report(
                &preview,
                &plan.destination.reservations,
                &plan.destination.source_allocations,
                &plan.preservation,
            )
        }
        (Some(_), None, _) | (None, Some(_), _) => {
            return Err("preview direction does not match the inspected source".into());
        }
        (None, None, _) => {
            return Err("complete normalized inventory is required for preview".into());
        }
        (Some(_), Some(_), _) => {
            return Err(
                "inspection unexpectedly contains normalized evidence for two filesystems".into(),
            );
        }
    };
    Ok(PreviewJobSuccess {
        profile: inspection.profile,
        target,
        report,
    })
}

fn build_candidate_export(
    source_path: &str,
    output_path: &Path,
    mode: GuaranteeMode,
) -> Result<ExportJobSuccess, String> {
    let image = ImageFile::open(source_path).map_err(|error| error.to_string())?;
    let inspection = inspect_open_image(&image).map_err(|error| error.to_string())?;
    let target = opposite_filesystem(inspection.profile.filesystem);
    if target == FileSystem::Unknown {
        return Err("recognized image has unknown filesystem".into());
    }
    let evidence = match (
        inspection.normalized_exfat.as_deref(),
        inspection.normalized_ntfs.as_deref(),
        target,
    ) {
        (Some(normalized), None, FileSystem::Ntfs) => {
            let plan = plan_lossless_exfat_to_ntfs(
                normalized,
                mode,
                ExfatToNtfsOptions::default(),
                ExfatToNtfsLimits::default(),
            )
            .map_err(|error| format!("cross-format plan refused: {error}"))?;
            let preview =
                preview_ntfs_phase_writes(&image, &plan.destination, PreimageLimits::default())
                    .map_err(|error| format!("phase preview failed: {error}"))?;
            export_gui_candidate(
                &image,
                output_path,
                &preview,
                &plan.target_graph,
                &plan.preservation,
            )?
        }
        (None, Some(normalized), FileSystem::ExFat) => {
            let plan = plan_lossless_ntfs_to_exfat(
                normalized,
                mode,
                NtfsToExfatOptions::default(),
                NtfsToExfatLimits::default(),
            )
            .map_err(|error| format!("cross-format plan refused: {error}"))?;
            let preview =
                preview_exfat_phase_writes(&image, &plan.destination, PreimageLimits::default())
                    .map_err(|error| format!("phase preview failed: {error}"))?;
            export_gui_candidate(
                &image,
                output_path,
                &preview,
                &plan.target_graph,
                &plan.preservation,
            )?
        }
        (Some(_), None, _) | (None, Some(_), _) => {
            return Err("conversion direction does not match the inspected source".into());
        }
        (None, None, _) => {
            return Err("complete normalized inventory is required for conversion".into());
        }
        (Some(_), Some(_), _) => {
            return Err("inspection contains evidence for two filesystems".into());
        }
    };
    Ok(ExportJobSuccess {
        profile: inspection.profile,
        target,
        source_path: source_path.to_owned(),
        evidence,
    })
}

impl eframe::App for StarConverterApp {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_background_jobs();
        if self.jobs.is_busy() {
            root.ctx().request_repaint_after(Duration::from_millis(75));
        }
        Self::show_header(root);
        self.show_footer(root);
        self.show_source_rail(root);
        self.show_activity_rail(root);
        self.show_workbench(root);
    }
}

impl StarConverterApp {
    fn show_header(root: &mut egui::Ui) {
        egui::Panel::top("header")
            .frame(
                Frame::new()
                    .fill(VOID)
                    .stroke(Stroke::new(1.0, LINE))
                    .inner_margin(Margin::symmetric(20, 12)),
            )
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("[ STAR :: CONVERTER ]")
                            .monospace()
                            .size(18.0)
                            .color(INK),
                    );
                    ui.label(RichText::new("::").monospace().color(FAINT));
                    ui.label(
                        RichText::new("FILESYSTEM TRANSFORMATION WORKBENCH")
                            .monospace()
                            .size(12.0)
                            .color(MUTED),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        status_label(ui, "COPY-ONLY BUILD", WORKING);
                    });
                });
            });
    }

    fn show_footer(&mut self, root: &mut egui::Ui) {
        egui::Panel::bottom("footer")
            .frame(
                Frame::new()
                    .fill(VOID)
                    .stroke(Stroke::new(1.0, LINE))
                    .inner_margin(Margin::symmetric(20, 12)),
            )
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("[SAFE] SOURCE WRITES DISABLED")
                            .monospace()
                            .color(READY),
                    );
                    ui.label(
                        RichText::new(
                            "Sources are read-only; exports create new files; device paths are refused.",
                        )
                        .monospace()
                        .color(MUTED),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.add_enabled(false, Button::new("Convert"))
                            .on_disabled_hover_text(
                                "In-place and physical conversion remain locked behind activation gates.",
                            );
                        let idle = !self.jobs.is_busy();
                        let export_enabled = idle && self.mode != GuaranteeMode::ContentOnly;
                        if ui
                            .add_enabled(export_enabled, Button::new("Export new image"))
                            .on_disabled_hover_text(
                                "Content-only is preview-only; choose strict or escrow to export.",
                            )
                            .clicked()
                        {
                            self.export_new_image();
                        }
                        if ui
                            .add_enabled(idle, Button::new("Preview exact"))
                            .clicked()
                        {
                            self.preview_image();
                        }
                        if ui
                            .add_enabled(idle, Button::new("Analyze source"))
                            .clicked()
                        {
                            if self.image_path.trim().is_empty() {
                                self.activity
                                    .push("00:00:00  [READY] synthetic plan refreshed".into());
                                self.replan();
                            } else {
                                self.analyze_image();
                            }
                        }
                        if ui.button("Save plan").clicked() {
                            self.save_plan();
                        }
                        if ui
                            .add_enabled(
                                !idle,
                                Button::new("Detach background job").fill(DANGER),
                            )
                            .on_hover_text(
                                "Ignore this result. An export already in progress may continue to safe completion.",
                            )
                            .clicked()
                        {
                            self.cancel_background_job();
                        }
                        if let Some(job) = self.jobs.active() {
                            ui.label(
                                RichText::new(format!("[WORKING] {}", job.kind.label()))
                                    .monospace()
                                    .color(WORKING),
                            );
                        }
                    });
                });
            });
    }

    fn show_source_rail(&mut self, root: &mut egui::Ui) {
        egui::Panel::left("source_rail")
            .resizable(false)
            .exact_size(270.0)
            .frame(
                Frame::new()
                    .fill(SURFACE)
                    .stroke(Stroke::new(1.0, LINE))
                    .inner_margin(Margin::same(16)),
            )
            .show(root, |ui| {
                ui.add(
                    Label::new(RichText::new(ASCII_MARK).monospace().size(13.0).color(INK))
                        .selectable(false),
                );
                self.show_source_selector(ui);
                self.show_source_identity(ui);
            });
    }

    fn show_source_selector(&mut self, ui: &mut egui::Ui) {
        ui.add_space(22.0);
        section_label(ui, "SOURCE");
        ui.add_space(8.0);
        let idle = !self.jobs.is_busy();
        if ui
            .add_enabled_ui(idle, |ui| {
                source_button(
                    ui,
                    !self.real_source && self.source.filesystem == FileSystem::ExFat,
                    "DEMO_ARCHIVE",
                    "exFAT  /  64.00 GiB",
                )
            })
            .inner
            .clicked()
        {
            self.select_exfat_demo();
        }
        ui.add_space(6.0);
        if ui
            .add_enabled_ui(idle, |ui| {
                source_button(
                    ui,
                    !self.real_source && self.source.filesystem == FileSystem::Ntfs,
                    "DEMO_WORKSPACE",
                    "NTFS   /  64.00 GiB",
                )
            })
            .inner
            .clicked()
        {
            self.select_ntfs_demo();
        }
        ui.add_space(12.0);
        ui.add_enabled_ui(idle, |ui| self.show_image_path_picker(ui));
        if ui
            .add_enabled_ui(idle, |ui| {
                ui.add_sized(
                    [ui.available_width(), 44.0],
                    Button::new(RichText::new("+ ANALYZE IMAGE").monospace()),
                )
            })
            .inner
            .clicked()
        {
            self.analyze_image();
        }
        ui.label(
            RichText::new(&self.inspection_status)
                .monospace()
                .size(10.0)
                .color(if self.real_source { READY } else { MUTED }),
        );
    }

    fn show_image_path_picker(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let browse_width = 78.0;
            let path_width = (ui.available_width() - browse_width - 8.0).max(80.0);
            ui.add_sized(
                [path_width, 44.0],
                egui::TextEdit::singleline(&mut self.image_path).hint_text("C:\\path\\volume.img"),
            )
            .on_hover_text("Regular image file only. Raw-device namespaces are rejected.");
            if ui
                .add_sized([browse_width, 44.0], Button::new("Browse"))
                .clicked()
            {
                self.choose_image();
            }
        });
    }

    fn show_source_identity(&self, ui: &mut egui::Ui) {
        ui.add_space(28.0);
        section_label(ui, "SOURCE IDENTITY");
        ui.add_space(8.0);
        metadata_row(ui, "LABEL", &self.source.display_name);
        metadata_row(ui, "FORMAT", &self.source.filesystem.to_string());
        metadata_row(
            ui,
            "SECTOR",
            &format!("{} B", self.source.logical_sector_bytes),
        );
        metadata_row(
            ui,
            "CLUSTER",
            &format!("{} KiB", self.source.cluster_bytes / 1024),
        );
        metadata_row(
            ui,
            "HEALTH",
            match self.source.state.health {
                HealthState::Clean => "CLEAN",
                HealthState::Dirty => "DIRTY",
                HealthState::Unknown => "UNKNOWN",
            },
        );
    }

    fn show_activity_rail(&self, root: &mut egui::Ui) {
        egui::Panel::right("activity_rail")
            .resizable(true)
            .default_size(315.0)
            .min_size(240.0)
            .max_size(430.0)
            .frame(
                Frame::new()
                    .fill(SURFACE)
                    .stroke(Stroke::new(1.0, LINE))
                    .inner_margin(Margin::same(16)),
            )
            .show(root, |ui| {
                section_label(ui, "ACTIVITY :: SESSION");
                ui.add_space(10.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for entry in &self.activity {
                            ui.label(RichText::new(entry).monospace().size(11.0).color(MUTED));
                            ui.add_space(5.0);
                        }
                    });
            });
    }

    fn show_workbench(&mut self, root: &mut egui::Ui) {
        egui::CentralPanel::default()
            .frame(Frame::new().fill(VOID).inner_margin(Margin::same(24)))
            .show(root, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        self.show_direction(ui);
                        self.show_modes(ui);
                        self.show_preflight(ui);
                        self.show_phases(ui);
                        self.show_exact_preview(ui);
                        self.show_export_verification(ui);
                    });
            });
    }

    fn show_direction(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                section_label(ui, "CONVERSION DIRECTION");
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!("{}  ->  {}", self.source.filesystem, self.target))
                        .monospace()
                        .size(24.0)
                        .color(INK),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::TOP), |ui| {
                let (text, color) = if self.plan.is_ready() {
                    ("PREFLIGHT READY", READY)
                } else {
                    ("PREFLIGHT BLOCKED", DANGER)
                };
                status_label(ui, text, color);
            });
        });
    }

    fn show_modes(&mut self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        section_label(ui, "GUARANTEE MODE");
        ui.add_space(8.0);
        ui.add_enabled_ui(!self.jobs.is_busy(), |ui| {
            ui.columns(3, |columns| {
                mode_card(
                    &mut columns[0],
                    &mut self.mode,
                    GuaranteeMode::Strict,
                    "STRICT",
                    "Refuse anything that cannot round-trip natively.",
                );
                mode_card(
                    &mut columns[1],
                    &mut self.mode,
                    GuaranteeMode::Escrow,
                    "ESCROW",
                    "Keep source-only semantics in a durable capsule.",
                );
                mode_card(
                    &mut columns[2],
                    &mut self.mode,
                    GuaranteeMode::ContentOnly,
                    "CONTENT ONLY",
                    "Preserve bytes; report metadata downgrades.",
                );
            });
        });
        if self.mode != self.plan.mode {
            self.replan();
        }
    }

    fn show_preflight(&self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        section_label(ui, "PREFLIGHT REPORT");
        ui.add_space(8.0);
        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, LINE))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                preflight_row(ui, "IDENTITY", &self.source.stable_id, "PINNED", READY);
                preflight_row(
                    ui,
                    "GEOMETRY",
                    &format!(
                        "{} B sector / {} KiB cluster",
                        self.source.logical_sector_bytes,
                        self.source.cluster_bytes / 1024
                    ),
                    "SUPPORTED",
                    READY,
                );
                preflight_row(
                    ui,
                    "SPACE",
                    &self.source.free_bytes.map_or_else(
                        || "allocation metadata not scanned".to_owned(),
                        |free| {
                            format!(
                                "{} required / {} proven free",
                                format_bytes(self.plan.required_temporary_bytes),
                                format_bytes(free)
                            )
                        },
                    ),
                    if self.source.free_bytes.is_some() {
                        "PROVEN"
                    } else {
                        "UNKNOWN"
                    },
                    if self.source.free_bytes.is_some() {
                        WORKING
                    } else {
                        DANGER
                    },
                );

                for issue in &self.plan.issues {
                    let color = match issue.severity {
                        Severity::Info => READY,
                        Severity::Warning => WARNING,
                        Severity::Blocker => DANGER,
                    };
                    preflight_row(
                        ui,
                        issue.code,
                        &issue.message,
                        issue.severity.token(),
                        color,
                    );
                }
            });
    }

    fn show_phases(&self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        section_label(ui, "TRANSACTION PHASES");
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .max_height(190.0)
            .show(ui, |ui| {
                for phase in &self.plan.phases {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{:02}", phase.number))
                                .monospace()
                                .color(FAINT),
                        );
                        ui.label(RichText::new("::").monospace().color(LINE_STRONG));
                        ui.label(
                            RichText::new(format!("{:<10}", phase.name))
                                .monospace()
                                .color(INK),
                        );
                        ui.label(
                            RichText::new(phase.summary)
                                .monospace()
                                .size(12.0)
                                .color(MUTED),
                        );
                    });
                    ui.add_space(5.0);
                }
            });
    }

    fn show_exact_preview(&self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        section_label(ui, "EXACT IMAGE PREVIEW");
        ui.add_space(8.0);
        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, LINE))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(180.0)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(self.exact_preview.as_deref().unwrap_or(
                                "[IDLE] Select a regular image and choose Preview exact.\n\
                                 [SAFE] The preview captures before-images in memory and has no executor authority.",
                            ))
                            .monospace()
                            .size(11.0)
                            .color(if self.exact_preview.is_some() {
                                WORKING
                            } else {
                                MUTED
                            }),
                        );
                    });
            });
    }

    fn show_export_verification(&mut self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        section_label(ui, "VERIFY / RECOVER EXPORT");
        ui.add_space(8.0);
        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, LINE))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                ui.add_enabled_ui(!self.jobs.is_busy(), |ui| {
                    self.show_verification_inputs(ui);
                });
                self.show_verification_result(ui);
            });
        ui.add_space(24.0);
    }

    fn show_verification_inputs(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new("READ-ONLY :: prove a final candidate belongs to its escrow sidecar")
                .monospace()
                .size(11.0)
                .color(WORKING),
        );
        ui.label(
            RichText::new(
                "The original source is optional; select it to confirm source filesystem and full SHA-256.",
            )
            .monospace()
            .size(10.0)
            .color(MUTED),
        );
        ui.add_space(10.0);
        let (browse_candidate, candidate_changed) = verification_path_row(
            ui,
            "FINAL CANDIDATE",
            "verification_candidate_path",
            &mut self.verification_candidate_path,
            "C:\\path\\candidate.img",
            "Browse candidate…",
        );
        let (browse_escrow, escrow_changed) = verification_path_row(
            ui,
            "BOUND ESCROW",
            "verification_escrow_path",
            &mut self.verification_escrow_path,
            "C:\\path\\candidate.img.starconverter-escrow",
            "Browse escrow…",
        );
        let (browse_source, source_changed) = verification_path_row(
            ui,
            "ORIGINAL SOURCE (OPTIONAL)",
            "verification_source_path",
            &mut self.verification_source_path,
            "C:\\path\\original-source.img",
            "Browse source…",
        );
        if candidate_changed || escrow_changed || source_changed {
            self.clear_verification_result(
                "Verification input changed; the displayed evidence was cleared.",
            );
        }
        if browse_candidate {
            self.choose_verification_candidate();
        }
        if browse_escrow {
            self.choose_verification_escrow();
        }
        if browse_source {
            self.choose_verification_source();
        }
        self.show_verification_actions(ui);
    }

    fn show_verification_actions(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let ready = !self.verification_candidate_path.trim().is_empty()
                && !self.verification_escrow_path.trim().is_empty();
            if ui
                .add_enabled(
                    ready,
                    Button::new(
                        RichText::new("VERIFY EXPORT READ-ONLY")
                            .monospace()
                            .color(if ready { READY } else { FAINT }),
                    ),
                )
                .on_disabled_hover_text(
                    "Select both the final candidate and its bound escrow sidecar.",
                )
                .on_hover_text(
                    "Hash and inspect regular files only; no repair, mount, or activation is performed.",
                )
                .clicked()
            {
                self.verify_export_read_only();
            }
            if ui
                .add_enabled(
                    !self.verification_source_path.trim().is_empty(),
                    Button::new("Clear optional source"),
                )
                .clicked()
            {
                self.verification_source_path.clear();
                self.clear_verification_result(
                    "Original source cleared; candidate-only verification has not run.",
                );
            }
        });
        ui.label(
            RichText::new(&self.verification_status)
                .monospace()
                .size(10.0)
                .color(if self.verification_ok { READY } else { MUTED }),
        );
    }

    fn show_verification_result(&self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("verification_report_scroll")
            .max_height(230.0)
            .show(ui, |ui| {
                ui.label(
                    RichText::new(self.verification_report.as_deref().unwrap_or(
                        "[IDLE] No bound export has been verified in this session.\n\
                         [READ-ONLY] Candidate, escrow, and optional source must be regular files.",
                    ))
                    .monospace()
                    .size(11.0)
                    .color(if self.verification_ok { READY } else { MUTED }),
                );
                ui.add_space(8.0);
                ui.label(
                    RichText::new(INTERRUPTED_EXPORT_GUIDANCE)
                        .monospace()
                        .size(10.0)
                        .color(WARNING),
                );
            });
    }
}

fn verification_path_row(
    ui: &mut egui::Ui,
    label: &str,
    id_source: &'static str,
    path: &mut String,
    hint: &str,
    browse_label: &str,
) -> (bool, bool) {
    let label_response = ui.label(RichText::new(label).monospace().size(10.0).color(MUTED));
    let mut browse = false;
    let mut changed = false;
    ui.horizontal(|ui| {
        let browse_width = 124.0;
        let path_width = (ui.available_width() - browse_width - 8.0).max(120.0);
        changed = ui
            .add_sized(
                [path_width, 36.0],
                egui::TextEdit::singleline(path)
                    .id_source(id_source)
                    .hint_text(hint),
            )
            .labelled_by(label_response.id)
            .on_hover_text("Regular file path only; device namespaces are rejected.")
            .changed();
        browse = ui
            .add_sized([browse_width, 36.0], Button::new(browse_label))
            .clicked();
    });
    (browse, changed)
}

fn configure_style(context: &egui::Context) {
    let mut style = (*context.global_style()).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(14.0, 10.0);
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = VOID;
    style.visuals.window_fill = SURFACE;
    style.visuals.extreme_bg_color = VOID;
    style.visuals.faint_bg_color = RAISED;
    style.visuals.override_text_color = Some(INK);
    style.visuals.widgets.noninteractive.bg_fill = SURFACE;
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
    style.visuals.widgets.inactive.bg_fill = RAISED;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, LINE);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(23, 26, 29);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, LINE_STRONG);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(29, 32, 35);
    style.visuals.widgets.active.bg_stroke = Stroke::new(2.0, WORKING);
    style.visuals.selection.bg_fill = Color32::from_rgb(34, 40, 43);
    style.visuals.selection.stroke = Stroke::new(1.0, WORKING);
    style.text_styles.insert(
        TextStyle::Body,
        FontId::new(14.0, egui::FontFamily::Monospace),
    );
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(13.0, egui::FontFamily::Monospace),
    );
    context.set_global_style(style);
}

fn section_label(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(format!("[ {text} ]"))
            .monospace()
            .size(11.0)
            .color(MUTED),
    );
}

fn status_label(ui: &mut egui::Ui, text: &str, color: Color32) {
    Frame::new()
        .fill(RAISED)
        .stroke(Stroke::new(1.0, color))
        .inner_margin(Margin::symmetric(9, 5))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("[{text}]"))
                    .monospace()
                    .size(11.0)
                    .color(color),
            );
        });
}

fn source_button(ui: &mut egui::Ui, selected: bool, title: &str, detail: &str) -> egui::Response {
    let text = RichText::new(format!("{title}\n{detail}"))
        .monospace()
        .size(12.0)
        .color(if selected { INK } else { MUTED });
    ui.add_sized(
        [ui.available_width(), 58.0],
        Button::selectable(selected, text),
    )
}

fn metadata_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{label:<9}"))
                .monospace()
                .size(11.0)
                .color(FAINT),
        );
        ui.label(RichText::new(value).monospace().size(11.0).color(MUTED));
    });
}

fn mode_card(
    ui: &mut egui::Ui,
    selected_mode: &mut GuaranteeMode,
    mode: GuaranteeMode,
    title: &str,
    description: &str,
) {
    let selected = *selected_mode == mode;
    let response = Frame::new()
        .fill(if selected { RAISED } else { SURFACE })
        .stroke(Stroke::new(
            if selected { 2.0 } else { 1.0 },
            if selected { WORKING } else { LINE },
        ))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_min_height(76.0);
            ui.label(
                RichText::new(format!("[ {title} ]"))
                    .monospace()
                    .size(12.0)
                    .color(if selected { INK } else { MUTED }),
            );
            ui.label(
                RichText::new(description)
                    .monospace()
                    .size(11.0)
                    .color(MUTED),
            );
        })
        .response
        .interact(egui::Sense::click());
    if response.clicked() {
        *selected_mode = mode;
    }
}

fn preflight_row(ui: &mut egui::Ui, label: &str, value: &str, status: &str, color: Color32) {
    ui.horizontal(|ui| {
        ui.set_min_height(24.0);
        ui.label(
            RichText::new(format!("{label:<22}"))
                .monospace()
                .size(11.0)
                .color(FAINT),
        );
        ui.label(RichText::new(value).monospace().size(11.0).color(MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(format!("[{status}]"))
                    .monospace()
                    .size(10.0)
                    .color(color),
            );
        });
    });
    ui.separator();
}

fn format_bytes(bytes: u64) -> String {
    const GIB: u64 = 1_073_741_824;
    let whole = bytes / GIB;
    let mut hundredths = ((bytes % GIB) * 100 + GIB / 2) / GIB;
    if hundredths == 100 {
        hundredths = 0;
        return format!("{}.{hundredths:02} GiB", whole + 1);
    }
    format!("{whole}.{hundredths:02} GiB")
}

fn exact_preview_report(
    preview: &PhaseWritePreview,
    reservations: &[DestinationReservation],
    allocations: &[SourceAllocation],
    preservation: &PreservationReport,
) -> String {
    let writes = preview.writes();
    let forward_count =
        writes.target_staging.len() + writes.backup_boot.len() + writes.activation.len();
    let rollback_count = writes.target_staging_rollback.len()
        + writes.backup_boot_rollback.len()
        + writes.activation_rollback.len();
    let forward_bytes = writes
        .target_staging
        .iter()
        .chain(&writes.backup_boot)
        .chain(&writes.activation)
        .map(|write| write.write.bytes.len())
        .sum::<usize>();
    let rollback_bytes = writes
        .target_staging_rollback
        .iter()
        .chain(&writes.backup_boot_rollback)
        .chain(&writes.activation_rollback)
        .map(|write| write.bytes.len())
        .sum::<usize>();
    let staging_exclusions = allocations.iter().filter(|value| !value.movable).count();
    let escrow_bytes = preservation.escrow.as_ref().map_or(0, Vec::len);

    let mut report = String::new();
    let _ = writeln!(
        report,
        "[READ-ONLY] {} candidate",
        preview.target_filesystem()
    );
    let _ = writeln!(
        report,
        "policy={} / schema-v{} / escrow={} B",
        if preservation.permitted {
            "PERMITTED"
        } else {
            "REFUSED"
        },
        preservation.schema_version,
        escrow_bytes
    );
    let _ = writeln!(
        report,
        "reservations={} / source-spans={} / non-movable={staging_exclusions}",
        reservations.len(),
        allocations.len()
    );
    let _ = writeln!(
        report,
        "forward={forward_count} writes / {}",
        format_byte_count(forward_bytes)
    );
    let _ = writeln!(
        report,
        "rollback={rollback_count} writes / {}",
        format_byte_count(rollback_bytes)
    );
    let _ = writeln!(report, "activation=BLOCKED");
    for gap in preview.activation_gaps() {
        let _ = writeln!(report, "[BLOCK] {gap}");
    }
    report
        .push_str("[NO AUTHORITY] No bytes were written; this preview cannot invoke the executor.");
    report
}

fn export_gui_candidate(
    source: &ImageFile,
    output: &Path,
    preview: &PhaseWritePreview,
    target_graph: &ObjectGraph,
    preservation: &PreservationReport,
) -> Result<CandidateExportEvidence, String> {
    let escrow_path = preservation.escrow.as_ref().map(|_| {
        let mut name = output.as_os_str().to_os_string();
        name.push(".starconverter-escrow");
        PathBuf::from(name)
    });
    export_candidate_image(
        source,
        output,
        escrow_path.as_deref(),
        preview,
        target_graph,
        preservation,
        CandidateExportLimits::default(),
    )
    .map_err(|error| format!("candidate export failed: {error}"))
}

fn export_evidence_report(evidence: &CandidateExportEvidence) -> String {
    let mut report = String::new();
    let _ = writeln!(
        report,
        "[COMPLETE] copy-based {} candidate",
        evidence.target_filesystem
    );
    let _ = writeln!(report, "output={}", evidence.output_path.display());
    if let Some(path) = &evidence.escrow_path {
        let _ = writeln!(report, "escrow={}", path.display());
    }
    let _ = writeln!(
        report,
        "writes={} / replaced={} / manifest={}",
        evidence.applied_writes,
        format_byte_count(usize::try_from(evidence.replacement_bytes).unwrap_or(usize::MAX)),
        hex_digest(&evidence.manifest_sha256)
    );
    let _ = writeln!(
        report,
        "candidate_sha256={}",
        hex_digest(&evidence.candidate_sha256)
    );
    let _ = writeln!(
        report,
        "[SOURCE UNCHANGED] {} bytes / sha256={}",
        evidence.image_bytes,
        hex_digest(&evidence.source_sha256)
    );
    let _ = writeln!(
        report,
        "output_directory_durability={}",
        evidence.output_directory_durability
    );
    if let Some(durability) = evidence.escrow_directory_durability {
        let _ = writeln!(report, "escrow_directory_durability={durability}");
    }
    report.push_str(
        "[SAFE] Create-new regular output only; in-place and device activation remain locked.",
    );
    report
}

fn verification_evidence_report(evidence: &CandidateVerificationEvidence) -> String {
    let mut report = String::new();
    let _ = writeln!(
        report,
        "[VERIFIED] bound {} -> {} export",
        evidence.source_filesystem, evidence.target_filesystem
    );
    let _ = writeln!(report, "candidate={}", evidence.candidate_path.display());
    let _ = writeln!(report, "escrow={}", evidence.escrow_path.display());
    let _ = writeln!(report, "candidate_bytes={}", evidence.candidate_bytes);
    let _ = writeln!(
        report,
        "candidate_sha256={}",
        hex_digest(&evidence.candidate_sha256)
    );
    let _ = writeln!(
        report,
        "manifest_sha256={}",
        hex_digest(&evidence.manifest_sha256)
    );
    let _ = writeln!(
        report,
        "logical_bytes_hashed={}",
        evidence.logical_bytes_hashed
    );
    let _ = writeln!(
        report,
        "escrow_schema=v{} / records={}",
        evidence.escrow_schema_version, evidence.escrow_records
    );
    if let (Some(path), Some(bytes)) = (&evidence.source_path, evidence.source_bytes) {
        let _ = writeln!(report, "[SOURCE VERIFIED] {}", path.display());
        let _ = writeln!(report, "source_bytes={bytes}");
    } else {
        let _ = writeln!(
            report,
            "[SOURCE NOT CHECKED] original source was not supplied"
        );
    }
    let _ = writeln!(
        report,
        "source_sha256={}",
        hex_digest(&evidence.source_sha256)
    );
    report.push_str(
        "[READ-ONLY] No repair, mount, physical-device access, or in-place action was performed.",
    );
    report
}

fn verification_failure_report(message: &str) -> String {
    format!(
        "[FAILED] bound export verification\nreason={message}\n\
         [DO NOT USE] Treat the candidate as unverified. Follow the recovery guidance below."
    )
}

const fn missing_verification_path(candidate: &str, escrow: &str) -> Option<&'static str> {
    if candidate.is_empty() && escrow.is_empty() {
        Some("candidate and escrow paths are required")
    } else if candidate.is_empty() {
        Some("candidate path is required")
    } else if escrow.is_empty() {
        Some("escrow path is required")
    } else {
        None
    }
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn format_byte_count(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = KIB * KIB;
    let (divisor, suffix) = if bytes >= MIB {
        (MIB, "MiB")
    } else if bytes >= KIB {
        (KIB, "KiB")
    } else {
        return format!("{bytes} B");
    };
    let whole = bytes / divisor;
    let hundredths = ((bytes % divisor) * 100 + divisor / 2) / divisor;
    format!("{whole}.{hundredths:02} {suffix}")
}

fn plan_report(plan: &ConversionPlan) -> String {
    let mut report = String::from(
        "[ STAR :: CONVERTER ]\nANALYSIS PLAN :: NOT AN EXECUTABLE WRITE AUTHORIZATION\n\n",
    );
    let _ = writeln!(report, "source={}", plan.source.display_name);
    let _ = writeln!(report, "identity={}", plan.source.stable_id);
    let _ = writeln!(
        report,
        "direction={} -> {}",
        plan.source.filesystem, plan.target
    );
    let _ = writeln!(report, "guarantee={}", plan.mode);
    let _ = writeln!(report, "capacity_bytes={}", plan.source.capacity_bytes);
    let _ = writeln!(
        report,
        "proven_free_bytes={}",
        plan.source
            .free_bytes
            .map_or_else(|| "unknown".into(), |value| value.to_string())
    );
    let _ = writeln!(
        report,
        "temporary_reservation_bytes={}",
        plan.required_temporary_bytes
    );
    let _ = writeln!(report, "blockers={}", plan.blocker_count());
    let _ = writeln!(report, "warnings={}", plan.warning_count());
    report.push_str("\nISSUES\n");
    for issue in &plan.issues {
        let _ = writeln!(
            report,
            "[{}] {} :: {}",
            issue.severity.token(),
            issue.code,
            issue.message
        );
    }
    report.push_str("\nPHASES\n");
    for phase in &plan.phases {
        let _ = writeln!(
            report,
            "{:02} :: {:<10} {}",
            phase.number, phase.name, phase.summary
        );
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_is_deterministic() {
        let plan = Planner.plan(
            &VolumeProfile::demo_exfat(),
            FileSystem::Ntfs,
            GuaranteeMode::Strict,
        );
        let first = plan_report(&plan);
        assert_eq!(first, plan_report(&plan));
        assert!(first.contains("NOT AN EXECUTABLE WRITE AUTHORIZATION"));
        assert!(first.contains("direction=exFAT -> NTFS"));
    }

    #[test]
    fn verification_report_is_deterministic_and_explicitly_read_only() {
        let evidence = CandidateVerificationEvidence {
            candidate_path: PathBuf::from("candidate.img"),
            escrow_path: PathBuf::from("candidate.img.starconverter-escrow"),
            source_path: Some(PathBuf::from("source.img")),
            source_filesystem: FileSystem::ExFat,
            target_filesystem: FileSystem::Ntfs,
            candidate_bytes: 4096,
            source_bytes: Some(4096),
            source_sha256: [0x11; 32],
            candidate_sha256: [0x22; 32],
            manifest_sha256: [0x33; 32],
            logical_bytes_hashed: 2048,
            escrow_schema_version: 4,
            escrow_records: 1,
        };
        let first = verification_evidence_report(&evidence);
        assert_eq!(first, verification_evidence_report(&evidence));
        assert!(first.contains("[VERIFIED] bound exFAT -> NTFS export"));
        assert!(first.contains("[SOURCE VERIFIED] source.img"));
        assert!(first.contains("physical-device access"));
    }

    #[test]
    fn verification_inputs_and_recovery_copy_fail_closed() {
        assert_eq!(
            missing_verification_path("", ""),
            Some("candidate and escrow paths are required")
        );
        assert_eq!(
            missing_verification_path("candidate.img", ""),
            Some("escrow path is required")
        );
        assert_eq!(
            missing_verification_path("", "escrow.bin"),
            Some("candidate path is required")
        );
        assert_eq!(
            missing_verification_path("candidate.img", "escrow.bin"),
            None
        );
        assert!(INTERRUPTED_EXPORT_GUIDANCE.contains(".starconverter-partial-*"));
        assert!(INTERRUPTED_EXPORT_GUIDANCE.contains("original source was opened read-only"));
        assert!(verification_failure_report("hash mismatch").contains("[DO NOT USE]"));
    }

    #[test]
    fn background_queue_applies_only_the_current_generation() {
        let mut jobs = BackgroundJobs::new();
        jobs.active = Some(ActiveJob {
            id: 2,
            kind: JobKind::Preview,
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        jobs.sender
            .send(JobMessage {
                id: 1,
                outcome: JobOutcome::Failed {
                    kind: JobKind::Inspect,
                    message: "stale".into(),
                },
            })
            .unwrap();
        jobs.sender
            .send(JobMessage {
                id: 2,
                outcome: JobOutcome::Failed {
                    kind: JobKind::Preview,
                    message: "current".into(),
                },
            })
            .unwrap();

        let Some(JobOutcome::Failed { kind, message }) = jobs.take_ready() else {
            panic!("current result should be delivered");
        };
        assert_eq!(kind, JobKind::Preview);
        assert_eq!(message, "current");
        assert!(!jobs.is_busy());
    }

    #[test]
    fn detached_job_result_is_deterministically_ignored() {
        let mut jobs = BackgroundJobs::new();
        let cancelled = Arc::new(AtomicBool::new(false));
        jobs.active = Some(ActiveJob {
            id: 7,
            kind: JobKind::Export,
            cancelled: Arc::clone(&cancelled),
        });
        assert_eq!(jobs.cancel(), Some(JobKind::Export));
        assert!(cancelled.load(Ordering::Acquire));
        jobs.sender
            .send(JobMessage {
                id: 7,
                outcome: JobOutcome::Failed {
                    kind: JobKind::Export,
                    message: "must not surface".into(),
                },
            })
            .unwrap();

        assert!(jobs.take_ready().is_none());
        assert_eq!(
            job_result_disposition(None, 7),
            JobResultDisposition::IgnoreStale
        );
    }
}
