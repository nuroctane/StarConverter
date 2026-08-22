use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use eframe::egui::{
    self, Align, Button, Color32, FontId, Frame, IconData, Label, Layout, Margin, RichText, Stroke,
    TextStyle, Vec2,
};
use starconverter_core::candidate_export::{
    CandidateExportEvidence, CandidateExportLimits, export_candidate_image,
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

const ASCII_MARK: &str = r"       *
   .  /|\  .
---<  /_\  >---
   ' /___\ '
[ STAR :: CONVERTER ]";

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(Vec2::new(1180.0, 760.0))
            .with_min_inner_size(Vec2::new(760.0, 580.0))
            .with_icon(app_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "StarConverter",
        options,
        Box::new(|creation_context| Ok(Box::new(StarConverterApp::new(creation_context)))),
    )
}

fn app_icon() -> IconData {
    const SIZE: usize = 64;
    const DIMENSION: u32 = 64;
    const BACKGROUND: [u8; 4] = [5, 5, 6, 255];
    const INK_RGBA: [u8; 4] = [242, 244, 245, 255];
    const WORKING_RGBA: [u8; 4] = [168, 216, 255, 255];
    let mut rgba = vec![BACKGROUND; SIZE * SIZE];

    let mut point = |x: usize, y: usize, color: [u8; 4]| {
        if x < SIZE && y < SIZE {
            rgba[y * SIZE + x] = color;
        }
    };
    for delta in 0..=6 {
        point(32, 8 + delta, INK_RGBA);
        point(32, 20 - delta, INK_RGBA);
        point(26 + delta, 14, INK_RGBA);
        point(38 - delta, 14, INK_RGBA);
    }
    for y in 23..=49 {
        let half_width = (y - 23) / 2;
        point(32 - half_width, y, WORKING_RGBA);
        point(32 + half_width, y, WORKING_RGBA);
    }
    for x in 18..=46 {
        point(x, 50, WORKING_RGBA);
        point(x, 51, WORKING_RGBA);
    }
    for x in 24..=40 {
        point(x, 38, INK_RGBA);
    }

    IconData {
        rgba: rgba.into_iter().flatten().collect(),
        width: DIMENSION,
        height: DIMENSION,
    }
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
        let path = self.image_path.trim();
        if path.is_empty() {
            self.inspection_status = "Image path is required.".into();
            self.activity
                .push("00:00:00  [BLOCKED] image path is empty".into());
            return;
        }
        match inspect_image(path) {
            Ok(inspection) => {
                let inventory_status = if inspection.profile.inventory_complete {
                    "complete bounded inventory normalized"
                } else {
                    "inventory incomplete; conversion remains blocked"
                };
                self.target = match inspection.profile.filesystem {
                    FileSystem::ExFat => FileSystem::Ntfs,
                    FileSystem::Ntfs => FileSystem::ExFat,
                    FileSystem::Unknown => FileSystem::Unknown,
                };
                self.source = inspection.profile;
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
            Err(error) => {
                self.real_source = false;
                self.inspection_status = error.to_string();
                self.activity
                    .push(format!("00:00:00  [BLOCKED] inspection failed :: {error}"));
            }
        }
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

        let result = self.build_exact_preview(&source_path);
        match result {
            Ok(report) => {
                self.exact_preview = Some(report);
                self.inspection_status =
                    "Exact candidate and rollback before-images captured in memory; no writes performed."
                        .into();
                self.activity
                    .push("00:00:00  [SAFE]  exact read-only transaction preview ready".into());
            }
            Err(error) => {
                self.exact_preview = None;
                self.inspection_status.clone_from(&error);
                self.activity
                    .push(format!("00:00:00  [BLOCKED] preview refused :: {error}"));
            }
        }
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

        match self.build_candidate_export(&source_path, &output_path) {
            Ok(evidence) => {
                self.exact_preview = Some(export_evidence_report(&evidence));
                self.inspection_status =
                    "New target image exported and independently reinspected; source hash unchanged."
                        .into();
                self.activity.push(format!(
                    "00:00:00  [COMPLETE] copy-based {} image :: {}",
                    evidence.target_filesystem,
                    evidence.output_path.display()
                ));
            }
            Err(error) => {
                self.inspection_status.clone_from(&error);
                self.activity.push(format!(
                    "00:00:00  [BLOCKED] image export refused :: {error}"
                ));
            }
        }
    }

    fn build_exact_preview(&mut self, source_path: &str) -> Result<String, String> {
        let image = ImageFile::open(source_path).map_err(|error| error.to_string())?;
        let inspection = inspect_open_image(&image).map_err(|error| error.to_string())?;
        let target = match inspection.profile.filesystem {
            FileSystem::ExFat => FileSystem::Ntfs,
            FileSystem::Ntfs => FileSystem::ExFat,
            FileSystem::Unknown => return Err("recognized image has unknown filesystem".into()),
        };
        self.source = inspection.profile.clone();
        self.target = target;
        self.real_source = true;
        self.replan();
        match (
            inspection.normalized_exfat.as_deref(),
            inspection.normalized_ntfs.as_deref(),
            target,
        ) {
            (Some(normalized), None, FileSystem::Ntfs) => {
                let plan = plan_lossless_exfat_to_ntfs(
                    normalized,
                    self.mode,
                    ExfatToNtfsOptions::default(),
                    ExfatToNtfsLimits::default(),
                )
                .map_err(|error| format!("cross-format plan refused: {error}"))?;
                let preview =
                    preview_ntfs_phase_writes(&image, &plan.destination, PreimageLimits::default())
                        .map_err(|error| format!("phase preview failed: {error}"))?;
                Ok(exact_preview_report(
                    &preview,
                    &plan.destination.reservations,
                    &plan.destination.source_allocations,
                    &plan.preservation,
                ))
            }
            (None, Some(normalized), FileSystem::ExFat) => {
                let plan = plan_lossless_ntfs_to_exfat(
                    normalized,
                    self.mode,
                    NtfsToExfatOptions::default(),
                    NtfsToExfatLimits::default(),
                )
                .map_err(|error| format!("cross-format plan refused: {error}"))?;
                let preview = preview_exfat_phase_writes(
                    &image,
                    &plan.destination,
                    PreimageLimits::default(),
                )
                .map_err(|error| format!("phase preview failed: {error}"))?;
                Ok(exact_preview_report(
                    &preview,
                    &plan.destination.reservations,
                    &plan.destination.source_allocations,
                    &plan.preservation,
                ))
            }
            (Some(_), None, _) | (None, Some(_), _) => {
                Err("preview direction does not match the inspected source".into())
            }
            (None, None, _) => Err("complete normalized inventory is required for preview".into()),
            (Some(_), Some(_), _) => Err(
                "inspection unexpectedly contains normalized evidence for two filesystems".into(),
            ),
        }
    }

    fn build_candidate_export(
        &mut self,
        source_path: &str,
        output_path: &Path,
    ) -> Result<CandidateExportEvidence, String> {
        let image = ImageFile::open(source_path).map_err(|error| error.to_string())?;
        let inspection = inspect_open_image(&image).map_err(|error| error.to_string())?;
        let target = match inspection.profile.filesystem {
            FileSystem::ExFat => FileSystem::Ntfs,
            FileSystem::Ntfs => FileSystem::ExFat,
            FileSystem::Unknown => return Err("recognized image has unknown filesystem".into()),
        };
        self.source = inspection.profile.clone();
        self.target = target;
        self.real_source = true;
        self.replan();
        match (
            inspection.normalized_exfat.as_deref(),
            inspection.normalized_ntfs.as_deref(),
            target,
        ) {
            (Some(normalized), None, FileSystem::Ntfs) => {
                let plan = plan_lossless_exfat_to_ntfs(
                    normalized,
                    self.mode,
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
                )
            }
            (None, Some(normalized), FileSystem::ExFat) => {
                let plan = plan_lossless_ntfs_to_exfat(
                    normalized,
                    self.mode,
                    NtfsToExfatOptions::default(),
                    NtfsToExfatLimits::default(),
                )
                .map_err(|error| format!("cross-format plan refused: {error}"))?;
                let preview = preview_exfat_phase_writes(
                    &image,
                    &plan.destination,
                    PreimageLimits::default(),
                )
                .map_err(|error| format!("phase preview failed: {error}"))?;
                export_gui_candidate(
                    &image,
                    output_path,
                    &preview,
                    &plan.target_graph,
                    &plan.preservation,
                )
            }
            (Some(_), None, _) | (None, Some(_), _) => {
                Err("conversion direction does not match the inspected source".into())
            }
            (None, None, _) => {
                Err("complete normalized inventory is required for conversion".into())
            }
            (Some(_), Some(_), _) => Err("inspection contains evidence for two filesystems".into()),
        }
    }
}

impl eframe::App for StarConverterApp {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
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
                        let export_enabled = self.mode != GuaranteeMode::ContentOnly;
                        if ui
                            .add_enabled(export_enabled, Button::new("Export new image"))
                            .on_disabled_hover_text(
                                "Content-only is preview-only; choose strict or escrow to export.",
                            )
                            .clicked()
                        {
                            self.export_new_image();
                        }
                        if ui.button("Preview exact").clicked() {
                            self.preview_image();
                        }
                        if ui.button("Analyze source").clicked() {
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
                ui.add_space(22.0);
                section_label(ui, "SOURCE");
                ui.add_space(8.0);

                if source_button(
                    ui,
                    !self.real_source && self.source.filesystem == FileSystem::ExFat,
                    "DEMO_ARCHIVE",
                    "exFAT  /  64.00 GiB",
                )
                .clicked()
                {
                    self.select_exfat_demo();
                }

                ui.add_space(6.0);
                if source_button(
                    ui,
                    !self.real_source && self.source.filesystem == FileSystem::Ntfs,
                    "DEMO_WORKSPACE",
                    "NTFS   /  64.00 GiB",
                )
                .clicked()
                {
                    self.select_ntfs_demo();
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let browse_width = 78.0;
                    let path_width = (ui.available_width() - browse_width - 8.0).max(80.0);
                    ui.add_sized(
                        [path_width, 44.0],
                        egui::TextEdit::singleline(&mut self.image_path)
                            .hint_text("C:\\path\\volume.img"),
                    )
                    .on_hover_text("Regular image file only. Raw-device namespaces are rejected.");
                    if ui
                        .add_sized([browse_width, 44.0], Button::new("Browse"))
                        .clicked()
                    {
                        self.choose_image();
                    }
                });
                if ui
                    .add_sized(
                        [ui.available_width(), 44.0],
                        Button::new(RichText::new("+ ANALYZE IMAGE").monospace()),
                    )
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
            });
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
                self.show_direction(ui);
                self.show_modes(ui);
                self.show_preflight(ui);
                self.show_phases(ui);
                self.show_exact_preview(ui);
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
    report.push_str(
        "[SAFE] Create-new regular output only; in-place and device activation remain locked.",
    );
    report
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
    fn icon_is_complete_rgba_and_report_is_deterministic() {
        let icon = app_icon();
        assert_eq!(icon.width, 64);
        assert_eq!(icon.height, 64);
        assert_eq!(icon.rgba.len(), 64 * 64 * 4);

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
}
