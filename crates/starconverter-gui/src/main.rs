use eframe::egui::{
    self, Align, Button, Color32, FontId, Frame, Label, Layout, Margin, RichText, Stroke,
    TextStyle, Vec2,
};
use starconverter_core::{
    ConversionPlan, FileSystem, GuaranteeMode, Planner, SemanticFeature, Severity, VolumeProfile,
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
    activity: Vec<&'static str>,
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
            activity: vec![
                "00:00:00  [READY] UI initialized",
                "00:00:00  [SAFE]  raw-device backend absent",
                "00:00:00  [INFO]  synthetic demo source selected",
            ],
        }
    }

    fn replan(&mut self) {
        self.plan = Planner.plan(&self.source, self.target, self.mode);
    }

    fn select_exfat_demo(&mut self) {
        self.source = VolumeProfile::demo_exfat();
        self.target = FileSystem::Ntfs;
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
        self.replan();
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
                        status_label(ui, "READ-ONLY BUILD", WORKING);
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
                        RichText::new("[SAFE] RAW WRITES DISABLED")
                            .monospace()
                            .color(READY),
                    );
                    ui.label(
                        RichText::new("Select a demo profile to inspect planner behavior.")
                            .monospace()
                            .color(MUTED),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.add_enabled(false, Button::new("Convert"))
                            .on_disabled_hover_text(
                                "Physical conversion is locked behind the image-only safety gate.",
                            );
                        if ui.button("Analyze source").clicked() {
                            self.activity
                                .push("00:00:00  [READY] synthetic plan refreshed");
                            self.replan();
                        }
                        if ui.button("Save plan").clicked() {
                            self.activity
                                .push("00:00:00  [INFO]  save-plan backend pending");
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
                    self.source.filesystem == FileSystem::ExFat,
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
                    self.source.filesystem == FileSystem::Ntfs,
                    "DEMO_WORKSPACE",
                    "NTFS   /  64.00 GiB",
                )
                .clicked()
                {
                    self.select_ntfs_demo();
                }

                ui.add_space(12.0);
                ui.add_sized(
                    [ui.available_width(), 44.0],
                    Button::new(RichText::new("+ OPEN IMAGE...").monospace()),
                )
                .on_hover_text("Image-file discovery arrives with the read-only parser stage.");

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
                    if self.source.state.clean {
                        "CLEAN"
                    } else {
                        "DIRTY"
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
                            ui.label(RichText::new(*entry).monospace().size(11.0).color(MUTED));
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
                    ("READY", READY)
                } else {
                    ("BLOCKED", DANGER)
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
                    &format_bytes(self.plan.required_temporary_bytes),
                    "RESERVE",
                    WORKING,
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
        return format!("{}.{hundredths:02} GiB temporary", whole + 1);
    }
    format!("{whole}.{hundredths:02} GiB temporary")
}
