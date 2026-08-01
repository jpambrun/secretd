use std::{
    collections::{HashMap, HashSet},
    error::Error,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use egui::{
    self, Align, Align2, Color32, CornerRadius, FontId, Frame, Layout, Margin, RichText, Stroke,
    TextEdit,
};
use tray_icon::{
    TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};
use winit::event_loop::EventLoopProxy;
use zeroize::{Zeroize, Zeroizing};

use secretd::{
    aws::{AwsAccessLevel, AwsConfiguration, AwsLoginStatus, AwsTarget},
    controller::{
        AppSnapshot, ApprovalDecision, AuditAction, Controller, PendingAwsCredentialRequest,
        PendingRequest,
    },
    grants::GrantScope,
    ipc::{RequestServer, begin_aws_login},
    paths::{default_runtime_path, default_vault_path},
};

use crate::icon::{TrayStatus, tray_icon};

const BACKGROUND: Color32 = Color32::from_rgb(245, 247, 245);
const SURFACE: Color32 = Color32::WHITE;
const SURFACE_MUTED: Color32 = Color32::from_rgb(249, 250, 249);
const INK: Color32 = Color32::from_rgb(21, 33, 27);
const MUTED: Color32 = Color32::from_rgb(99, 113, 105);
const LINE: Color32 = Color32::from_rgb(218, 225, 221);
const LINE_STRONG: Color32 = Color32::from_rgb(190, 201, 195);
const GREEN: Color32 = Color32::from_rgb(20, 139, 94);
const GREEN_SOFT: Color32 = Color32::from_rgb(230, 245, 237);
const AMBER: Color32 = Color32::from_rgb(216, 145, 34);
const RED: Color32 = Color32::from_rgb(202, 67, 67);
const RED_SOFT: Color32 = Color32::from_rgb(255, 241, 241);

#[derive(Debug)]
pub enum AppEvent {
    Show,
    Toggle,
    Lock,
    StateChanged,
    Repaint(Duration),
    Quit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestDialogAction {
    None,
    Close,
    OpenMain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Secrets,
    Aws,
    Grants,
    Activity,
}

struct SecretDraft {
    original_name: Option<String>,
    name: String,
    group: String,
    value: Zeroizing<String>,
}

struct PasswordDraft {
    password: Zeroizing<String>,
    confirmation: Zeroizing<String>,
}

struct AwsTargetDraft {
    profile: String,
    account_id: String,
    account_name: String,
    email_address: String,
    roles: Vec<String>,
    read_only_role: String,
    admin_role: String,
    region: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AwsDraftStep {
    Connection,
    Aliases,
}

struct AwsDraft {
    step: AwsDraftStep,
    start_url: String,
    sso_region: String,
    targets: Vec<AwsTargetDraft>,
}

struct Toast {
    message: String,
    danger: bool,
    expires_at: Instant,
}

#[derive(Clone, Copy)]
struct RequestChoice {
    seconds: u64,
}

pub struct SecretDApp {
    controller: Arc<Mutex<Controller>>,
    notify: Arc<dyn Fn() + Send + Sync>,
    request_server: RequestServer,
    tray: TrayIcon,
    tray_menu: Menu,
    tray_status: TrayStatus,
    view: View,
    auth_password: Zeroizing<String>,
    auth_confirmation: Zeroizing<String>,
    auth_error: Option<String>,
    auth_focus_requested: bool,
    search: String,
    group_filter: Option<String>,
    secret_draft: Option<SecretDraft>,
    password_draft: Option<PasswordDraft>,
    aws_draft: Option<AwsDraft>,
    form_error: Option<String>,
    revealed: Option<(String, Zeroizing<String>)>,
    delete_confirmation: Option<String>,
    request_choices: HashMap<String, RequestChoice>,
    request_error: Option<String>,
    toast: Option<Toast>,
}

impl SecretDApp {
    pub fn new(
        event_proxy: EventLoopProxy<AppEvent>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let controller = Arc::new(Mutex::new(Controller::new(
            default_vault_path().map_err(std::io::Error::other)?,
        )));
        let notify_proxy = event_proxy.clone();
        let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let _ = notify_proxy.send_event(AppEvent::StateChanged);
        });
        let request_server = RequestServer::start(
            Arc::clone(&controller),
            default_runtime_path().map_err(std::io::Error::other)?,
            Arc::clone(&notify),
        )
        .map_err(std::io::Error::other)?;
        let snapshot = controller
            .lock()
            .map_err(|_| std::io::Error::other("SecretD state is unavailable"))?
            .snapshot();
        let tray_menu = Menu::new();
        rebuild_tray_menu(&tray_menu, &snapshot)?;
        let tray_status = tray_status(&snapshot);
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu.clone()))
            .with_icon(tray_icon(tray_status).map_err(std::io::Error::other)?)
            .with_icon_as_template(false)
            .with_tooltip("SecretD")
            .with_menu_on_left_click(false)
            .build()?;

        let menu_proxy = event_proxy.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let app_event = match event.id.as_ref() {
                "show" => Some(AppEvent::Show),
                "lock" => Some(AppEvent::Lock),
                "quit" => Some(AppEvent::Quit),
                _ => None,
            };
            if let Some(event) = app_event {
                let _ = menu_proxy.send_event(event);
            }
        }));
        TrayIconEvent::set_event_handler(Some(move |event| {
            if let TrayIconEvent::Click {
                button,
                button_state,
                ..
            } = event
                && should_toggle_for_tray_click(button, button_state)
            {
                let _ = event_proxy.send_event(AppEvent::Toggle);
            }
        }));

        Ok(Self {
            controller,
            notify,
            request_server,
            tray,
            tray_menu,
            tray_status,
            view: View::Secrets,
            auth_password: Zeroizing::new(String::new()),
            auth_confirmation: Zeroizing::new(String::new()),
            auth_error: None,
            auth_focus_requested: false,
            search: String::new(),
            group_filter: None,
            secret_draft: None,
            password_draft: None,
            aws_draft: None,
            form_error: None,
            revealed: None,
            delete_confirmation: None,
            request_choices: HashMap::new(),
            request_error: None,
            toast: None,
        })
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> bool {
        let quit = ui
            .ctx()
            .input(|input| input.modifiers.command && input.key_pressed(egui::Key::Q));
        ui.ctx().request_repaint_after(Duration::from_millis(500));
        let snapshot = self.snapshot();
        ui.painter().rect_filled(ui.max_rect(), 0, BACKGROUND);
        if !snapshot.vault_exists {
            self.auth_ui(ui, true);
        } else if !snapshot.unlocked {
            self.auth_ui(ui, false);
        } else {
            self.workspace_ui(ui, snapshot);
        }
        self.secret_editor(ui.ctx());
        self.password_editor(ui.ctx());
        self.aws_editor(ui.ctx());
        self.delete_dialog(ui.ctx());
        self.toast_ui(ui.ctx());
        quit
    }

    pub fn refresh_state(&mut self) {
        let snapshot = self.snapshot();
        if matches!(
            snapshot.aws_login,
            AwsLoginStatus::Starting
                | AwsLoginStatus::AwaitingUser(_)
                | AwsLoginStatus::Discovering
        ) {
            self.view = View::Aws;
        }
        if self.aws_draft.is_none()
            && snapshot.aws.as_ref().is_some_and(|aws| {
                aws.configuration.targets.is_empty() && !aws.discovered_accounts.is_empty()
            })
        {
            self.aws_draft = Some(aws_alias_draft(&snapshot));
            self.form_error = None;
        }
        self.refresh_tray(&snapshot);
    }

    pub fn has_access_requests(&self) -> bool {
        self.controller.lock().is_ok_and(|mut controller| {
            let snapshot = controller.snapshot();
            !snapshot.pending.is_empty() || !snapshot.pending_aws.is_empty()
        })
    }

    pub fn aws_login_in_progress(&self) -> bool {
        self.controller.lock().is_ok_and(|mut controller| {
            matches!(
                controller.snapshot().aws_login,
                AwsLoginStatus::Starting
                    | AwsLoginStatus::AwaitingUser(_)
                    | AwsLoginStatus::Discovering
            )
        })
    }

    pub fn lock(&mut self) {
        if let Ok(mut controller) = self.controller.lock() {
            controller.lock();
        }
        self.clear_sensitive_ui();
        self.refresh_state();
    }

    pub fn on_ui_closed(&mut self) {
        self.clear_sensitive_ui();
    }

    pub fn shutdown(&mut self) {
        self.lock();
        self.request_server.close();
    }

    fn snapshot(&self) -> AppSnapshot {
        self.controller
            .lock()
            .expect("SecretD controller mutex was poisoned")
            .snapshot()
    }

    fn refresh_tray(&mut self, snapshot: &AppSnapshot) {
        let status = tray_status(snapshot);
        if status != self.tray_status {
            if let Ok(icon) = tray_icon(status) {
                let _ = self.tray.set_icon_with_as_template(Some(icon), false);
            }
            self.tray_status = status;
        }
        let pending_count = snapshot.pending.len() + snapshot.pending_aws.len();
        let tooltip = if pending_count > 0 {
            format!(
                "SecretD — {} request{} pending",
                pending_count,
                if pending_count == 1 { "" } else { "s" }
            )
        } else if snapshot.unlocked {
            format!(
                "SecretD — unlocked · {} credentials",
                snapshot.secrets.len()
            )
        } else {
            "SecretD — locked".into()
        };
        let _ = self.tray.set_tooltip(Some(tooltip));
        let _ = rebuild_tray_menu(&self.tray_menu, snapshot);
    }

    fn auth_ui(&mut self, ui: &mut egui::Ui, creating: bool) {
        let enter = ui.ctx().input(|input| input.key_pressed(egui::Key::Enter));
        Frame::new().fill(BACKGROUND).show(ui, |ui| {
            ui.vertical_centered(|ui| {
                let estimated_height = if creating { 430.0 } else { 350.0 };
                ui.add_space(((ui.available_height() - estimated_height) / 2.0).max(20.0));
                Frame::new()
                    .fill(SURFACE)
                    .stroke(Stroke::new(1.0, LINE))
                    .corner_radius(20)
                    .inner_margin(Margin::same(32))
                    .show(ui, |ui| {
                        ui.set_width(420.0);
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                brand_mark(ui);
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new("SecretD")
                                            .size(17.0)
                                            .strong()
                                            .color(INK),
                                    );
                                    ui.label(
                                        RichText::new("LOCAL ENCRYPTED VAULT")
                                            .size(10.0)
                                            .strong()
                                            .color(MUTED),
                                    );
                                });
                            });
                            ui.add_space(24.0);
                            ui.label(
                                RichText::new(if creating {
                                    "Create your vault"
                                } else {
                                    "Welcome back"
                                })
                                .size(26.0)
                                .strong()
                                .color(INK),
                            );
                            ui.label(
                                RichText::new(if creating {
                                    "Protect credentials in an encrypted vault that stays on this Mac."
                                } else {
                                    "Unlock your vault to manage credentials and approve access."
                                })
                                .size(14.0)
                                .color(MUTED),
                            );
                            ui.add_space(22.0);
                            field_label(ui, "Master password");
                            let password = singleline_field(
                                ui,
                                &mut *self.auth_password,
                                "Enter your master password",
                                true,
                                f32::INFINITY,
                            );
                            if !self.auth_focus_requested {
                                password.request_focus();
                                self.auth_focus_requested = true;
                            }
                            ui.label(
                                RichText::new(if creating {
                                    "Use a password you can remember. It never leaves this device."
                                } else {
                                    "Your password is only used to decrypt the local vault."
                                })
                                .size(11.0)
                                .color(MUTED),
                            );
                            let mut confirmation_focused = false;
                            if creating {
                                ui.add_space(8.0);
                                field_label(ui, "Confirm password");
                                let confirmation = singleline_field(
                                    ui,
                                    &mut *self.auth_confirmation,
                                    "Enter it again",
                                    true,
                                    f32::INFINITY,
                                );
                                confirmation_focused = confirmation.has_focus();
                            }
                            if let Some(error) = &self.auth_error {
                                ui.add_space(4.0);
                                error_banner(ui, error);
                            }
                            ui.add_space(12.0);
                            let ready = !self.auth_password.is_empty()
                                && (!creating || !self.auth_confirmation.is_empty());
                            let submit = full_primary_button(
                                ui,
                                if creating {
                                    "Create encrypted vault"
                                } else {
                                    "Unlock vault"
                                },
                                ready,
                            )
                            .clicked()
                                || (enter
                                    && ready
                                    && (password.has_focus() || confirmation_focused));
                            if submit {
                                self.submit_auth(creating);
                            }
                            ui.add_space(6.0);
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    RichText::new("AES-256 encrypted • PBKDF2 protected")
                                        .size(10.0)
                                        .color(MUTED),
                                );
                            });
                        });
                    });
            });
        });
    }

    fn submit_auth(&mut self, creating: bool) {
        self.auth_error = None;
        if creating && *self.auth_password != *self.auth_confirmation {
            self.auth_error = Some("Passwords do not match".into());
            return;
        }
        let result = self
            .controller
            .lock()
            .map_err(|_| "SecretD state is unavailable".to_string())
            .and_then(|mut controller| {
                if creating {
                    controller
                        .create_vault(&self.auth_password)
                        .map_err(|error| error.to_string())
                } else {
                    controller
                        .unlock(&self.auth_password)
                        .map_err(|error| error.to_string())
                }
            });
        match result {
            Ok(()) => {
                self.auth_password.zeroize();
                self.auth_confirmation.zeroize();
                self.refresh_state();
            }
            Err(error) => self.auth_error = Some(error),
        }
    }

    fn workspace_ui(&mut self, ui: &mut egui::Ui, snapshot: AppSnapshot) {
        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, LINE))
            .inner_margin(Margin::symmetric(28, 16))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    brand_mark(ui);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("SecretD").size(18.0).strong().color(INK));
                        ui.label(RichText::new("Local credential vault").small().color(MUTED));
                    });
                    status_pill(ui, "Vault unlocked", GREEN, GREEN_SOFT);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if secondary_button(ui, "Lock").clicked() {
                            self.lock();
                        }
                        if secondary_button(ui, "Change password").clicked() {
                            self.password_draft = Some(PasswordDraft {
                                password: Zeroizing::new(String::new()),
                                confirmation: Zeroizing::new(String::new()),
                            });
                            self.form_error = None;
                        }
                    });
                });
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    nav_button(
                        ui,
                        &mut self.view,
                        View::Secrets,
                        "Credentials",
                        snapshot.secrets.len(),
                    );
                    nav_button(
                        ui,
                        &mut self.view,
                        View::Aws,
                        "AWS SSO",
                        snapshot
                            .aws
                            .as_ref()
                            .map_or(0, |aws| aws.configuration.targets.len()),
                    );
                    nav_button(
                        ui,
                        &mut self.view,
                        View::Grants,
                        "Active access",
                        snapshot.grants.len() + snapshot.aws_grants.len(),
                    );
                    nav_button(
                        ui,
                        &mut self.view,
                        View::Activity,
                        "Activity",
                        snapshot.audit.len(),
                    );
                });
            });
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                Frame::new()
                    .inner_margin(Margin::symmetric(36, 30))
                    .show(ui, |ui| match self.view {
                        View::Secrets => self.secrets_ui(ui, &snapshot),
                        View::Aws => self.aws_ui(ui, &snapshot),
                        View::Grants => self.grants_ui(ui, &snapshot),
                        View::Activity => self.activity_ui(ui, &snapshot),
                    });
            });
    }

    fn secrets_ui(&mut self, ui: &mut egui::Ui, snapshot: &AppSnapshot) {
        section_header(
            ui,
            "Credentials",
            "Manage secrets and organize related access with groups.",
        );
        ui.horizontal(|ui| {
            singleline_field(
                ui,
                &mut self.search,
                "Search credentials or groups…",
                false,
                310.0,
            );
            let groups: Vec<_> = snapshot
                .secrets
                .iter()
                .filter_map(|secret| secret.group.clone())
                .collect();
            egui::ComboBox::from_id_salt("group-filter")
                .selected_text(self.group_filter.as_deref().unwrap_or("All groups"))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.group_filter, None, "All groups");
                    for group in groups {
                        ui.selectable_value(&mut self.group_filter, Some(group.clone()), group);
                    }
                });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if primary_button(ui, "+ New credential").clicked() {
                    self.secret_draft = Some(SecretDraft {
                        original_name: None,
                        name: String::new(),
                        group: String::new(),
                        value: Zeroizing::new(String::new()),
                    });
                    self.form_error = None;
                }
            });
        });
        ui.add_space(14.0);

        let query = self.search.to_ascii_lowercase();
        let visible: Vec<_> = snapshot
            .secrets
            .iter()
            .filter(|secret| {
                (query.is_empty()
                    || secret.name.to_ascii_lowercase().contains(&query)
                    || secret
                        .group
                        .as_deref()
                        .is_some_and(|group| group.to_ascii_lowercase().contains(&query)))
                    && self
                        .group_filter
                        .as_deref()
                        .is_none_or(|group| secret.group.as_deref() == Some(group))
            })
            .cloned()
            .collect();
        if visible.is_empty() {
            empty_state(
                ui,
                if snapshot.secrets.is_empty() {
                    "Your vault is empty"
                } else {
                    "No matching credentials"
                },
            );
            return;
        }

        let mut reveal = None;
        let mut edit = None;
        let mut delete = None;
        for secret in visible {
            Frame::new()
                .fill(SURFACE)
                .stroke(Stroke::new(1.0, LINE))
                .corner_radius(14)
                .inner_margin(Margin::same(16))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        credential_mark(ui);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&secret.name).size(14.0).strong().color(INK));
                            ui.label(
                                RichText::new(secret.group.as_deref().unwrap_or("No group"))
                                    .small()
                                    .color(MUTED),
                            );
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if danger_button(ui, "Delete").clicked() {
                                delete = Some(secret.name.clone());
                            }
                            if secondary_button(ui, "Edit").clicked() {
                                edit = Some(secret.name.clone());
                            }
                            if secondary_button(
                                ui,
                                if self
                                    .revealed
                                    .as_ref()
                                    .is_some_and(|(name, _)| name == &secret.name)
                                {
                                    "Hide"
                                } else {
                                    "Reveal"
                                },
                            )
                            .clicked()
                            {
                                reveal = Some(secret.name.clone());
                            }
                        });
                    });
                    if let Some((_, value)) = self
                        .revealed
                        .as_mut()
                        .filter(|(name, _)| name == &secret.name)
                    {
                        ui.separator();
                        ui.label(RichText::new("Secret value").small().strong().color(MUTED));
                        ui.add(
                            TextEdit::multiline(&mut **value)
                                .desired_width(f32::INFINITY)
                                .interactive(false),
                        );
                    }
                });
            ui.add_space(8.0);
        }
        if let Some(name) = reveal {
            if self
                .revealed
                .as_ref()
                .is_some_and(|(revealed, _)| revealed == &name)
            {
                self.revealed = None;
            } else {
                match self
                    .controller
                    .lock()
                    .map_err(|_| "SecretD state is unavailable".to_string())
                    .and_then(|controller| {
                        controller
                            .reveal_secret(&name)
                            .map_err(|error| error.to_string())
                    }) {
                    Ok(value) => self.revealed = Some((name, value)),
                    Err(error) => self.toast(error, true),
                }
            }
        }
        if let Some(name) = edit {
            let result = self
                .controller
                .lock()
                .map_err(|_| "SecretD state is unavailable".to_string())
                .and_then(|controller| {
                    controller
                        .reveal_secret(&name)
                        .map_err(|error| error.to_string())
                });
            match result {
                Ok(value) => {
                    let group = snapshot
                        .secrets
                        .iter()
                        .find(|secret| secret.name == name)
                        .and_then(|secret| secret.group.clone())
                        .unwrap_or_default();
                    self.secret_draft = Some(SecretDraft {
                        original_name: Some(name.clone()),
                        name,
                        group,
                        value,
                    });
                    self.form_error = None;
                }
                Err(error) => self.toast(error, true),
            }
        }
        if let Some(name) = delete {
            self.delete_confirmation = Some(name);
        }
    }

    fn aws_ui(&mut self, ui: &mut egui::Ui, snapshot: &AppSnapshot) {
        section_header(
            ui,
            "AWS IAM Identity Center",
            "Sign in first, then turn discovered AWS accounts into local profiles.",
        );
        let login_in_progress = matches!(
            snapshot.aws_login,
            AwsLoginStatus::Starting
                | AwsLoginStatus::AwaitingUser(_)
                | AwsLoginStatus::Discovering
        );
        ui.horizontal(|ui| {
            let edit = ui.add_enabled_ui(!login_in_progress, |ui| {
                secondary_button(
                    ui,
                    if snapshot.aws.is_some() {
                        "Change connection"
                    } else {
                        "Connect AWS"
                    },
                )
            });
            if edit.inner.clicked() {
                self.aws_draft = Some(aws_connection_draft(snapshot));
                self.form_error = None;
            }
            if snapshot
                .aws
                .as_ref()
                .is_some_and(|aws| !aws.discovered_accounts.is_empty())
                && !login_in_progress
                && secondary_button(ui, "Manage aliases").clicked()
            {
                self.aws_draft = Some(aws_alias_draft(snapshot));
                self.form_error = None;
            }
            if snapshot.aws.is_some()
                && !login_in_progress
                && primary_button(ui, "Sign in and refresh accounts").clicked()
            {
                match begin_aws_login(Arc::clone(&self.controller), Arc::clone(&self.notify)) {
                    Ok(()) => self.toast("AWS SSO login started", false),
                    Err(error) => self.toast(error, true),
                }
            }
        });
        ui.add_space(14.0);

        match &snapshot.aws_login {
            AwsLoginStatus::Starting => {
                status_pill(ui, "Starting AWS login…", AMBER, SURFACE_MUTED);
            }
            AwsLoginStatus::AwaitingUser(authorization) => {
                Frame::new()
                    .fill(GREEN_SOFT)
                    .stroke(Stroke::new(1.0, LINE))
                    .corner_radius(14)
                    .inner_margin(Margin::same(16))
                    .show(ui, |ui| {
                        ui.label(RichText::new("Complete sign-in in your browser").strong());
                        ui.label(
                            RichText::new(format!(
                                "Verification code: {}",
                                authorization.user_code
                            ))
                            .monospace()
                            .color(INK),
                        );
                        let url = authorization
                            .verification_uri_complete
                            .as_deref()
                            .unwrap_or(&authorization.verification_uri);
                        ui.hyperlink_to("Open AWS sign-in", url);
                        ui.label(
                            RichText::new(format!(
                                "This request expires in {}",
                                duration_until_seconds(authorization.expires_at)
                            ))
                            .small()
                            .color(MUTED),
                        );
                    });
                ui.add_space(12.0);
            }
            AwsLoginStatus::Discovering => {
                status_pill(ui, "Loading AWS accounts and roles…", AMBER, SURFACE_MUTED);
                ui.add_space(12.0);
            }
            AwsLoginStatus::LoggedIn { expires_at } => {
                status_pill(
                    ui,
                    &format!(
                        "Signed in · access token expires in {}",
                        duration_until_seconds(*expires_at)
                    ),
                    GREEN,
                    GREEN_SOFT,
                );
                ui.add_space(12.0);
            }
            AwsLoginStatus::Failed(error) => {
                error_banner(ui, error);
                ui.add_space(12.0);
            }
            AwsLoginStatus::Idle => {}
        }

        let Some(aws) = &snapshot.aws else {
            empty_state(ui, "Step 1 · Enter your AWS access portal URL to begin");
            return;
        };
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Encrypted SSO connection")
                    .strong()
                    .color(INK),
            );
            status_pill(
                ui,
                if aws.logged_in {
                    "Session available"
                } else {
                    "Sign-in required"
                },
                if aws.logged_in { GREEN } else { AMBER },
                SURFACE_MUTED,
            );
        });
        ui.label(
            RichText::new(format!(
                "{} · {}",
                aws.configuration.start_url, aws.configuration.sso_region
            ))
            .small()
            .color(MUTED),
        );
        ui.add_space(12.0);
        if !aws.discovery_complete {
            Frame::new()
                .fill(SURFACE)
                .stroke(Stroke::new(1.0, LINE))
                .corner_radius(14)
                .inner_margin(Margin::same(16))
                .show(ui, |ui| {
                    ui.label(RichText::new("Step 2 · Discover your accounts").strong());
                    ui.label(
                        RichText::new(
                            "Sign in to AWS. SecretD will load the accounts and roles assigned to you.",
                        )
                        .small()
                        .color(MUTED),
                    );
                });
            return;
        }
        if aws.discovered_accounts.is_empty() {
            empty_state(ui, "AWS returned no accounts assigned to this identity");
            return;
        }
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} AWS accounts discovered",
                    aws.discovered_accounts.len()
                ))
                .strong()
                .color(INK),
            );
            if aws.configuration.targets.is_empty() {
                status_pill(ui, "Aliases required", AMBER, SURFACE_MUTED);
            }
        });
        ui.label(
            RichText::new("Assign an alias to expose an account as an AWS profile.")
                .small()
                .color(MUTED),
        );
        if aws.configuration.targets.is_empty()
            && primary_button(ui, "Assign profile aliases").clicked()
        {
            self.aws_draft = Some(aws_alias_draft(snapshot));
            self.form_error = None;
        }
        ui.add_space(12.0);
        for target in &aws.configuration.targets {
            Frame::new()
                .fill(SURFACE)
                .stroke(Stroke::new(1.0, LINE))
                .corner_radius(14)
                .inner_margin(Margin::same(16))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(&target.profile)
                                .size(16.0)
                                .strong()
                                .color(INK),
                        );
                        ui.label(RichText::new(&target.account_id).monospace().color(MUTED));
                    });
                    ui.label(
                        RichText::new(format!(
                            "Read-only: {} · Admin: {}{}",
                            target.read_only_role,
                            target.admin_role,
                            if target.region.is_empty() {
                                String::new()
                            } else {
                                format!(" · {}", target.region)
                            }
                        ))
                        .small()
                        .color(MUTED),
                    );
                });
            ui.add_space(8.0);
        }
    }

    pub fn request_dialog_ui(&mut self, ui: &mut egui::Ui) -> RequestDialogAction {
        ui.ctx().request_repaint_after(Duration::from_millis(500));
        let snapshot = self.snapshot();
        ui.painter().rect_filled(ui.max_rect(), 0, BACKGROUND);
        if snapshot.pending.is_empty() && snapshot.pending_aws.is_empty() {
            return RequestDialogAction::Close;
        }
        let mut response = None;
        let mut aws_response = None;
        let mut action = RequestDialogAction::None;
        Frame::new()
            .fill(BACKGROUND)
            .inner_margin(Margin::same(22))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    brand_mark(ui);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Access request")
                                .size(19.0)
                                .strong()
                                .color(INK),
                        );
                        ui.label(
                            RichText::new("Review the requesting process before granting access")
                                .small()
                                .color(MUTED),
                        );
                    });
                });
                if let Some(error) = &self.request_error {
                    ui.add_space(10.0);
                    error_banner(ui, error);
                }
                ui.add_space(14.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let show_aws =
                            match (snapshot.pending_aws.first(), snapshot.pending.first()) {
                                (Some(aws), Some(secret)) => {
                                    aws.requested_at <= secret.requested_at
                                }
                                (Some(_), None) => true,
                                _ => false,
                            };
                        if show_aws {
                            let request = snapshot
                                .pending_aws
                                .first()
                                .expect("AWS request was selected");
                            Frame::new()
                                .fill(SURFACE)
                                .stroke(Stroke::new(
                                    1.0,
                                    if request.verified { LINE } else { AMBER },
                                ))
                                .corner_radius(14)
                                .inner_margin(Margin::same(18))
                                .show(ui, |ui| {
                                    aws_request_heading(ui, request);
                                    ui.add_space(8.0);
                                    ui.label(
                                        RichText::new(format!(
                                            "{} · PID {}",
                                            request.origin.executable, request.origin.pid
                                        ))
                                        .color(MUTED),
                                    );
                                    egui::CollapsingHeader::new("Process tree").show(ui, |ui| {
                                        for (index, process) in
                                            request.process_tree.iter().enumerate()
                                        {
                                            ui.monospace(format!(
                                                "{}{} [{}]",
                                                "  ".repeat(index),
                                                process.command,
                                                process.pid
                                            ));
                                        }
                                    });
                                    ui.add_space(8.0);
                                    ui.horizontal_wrapped(|ui| {
                                        if danger_button(ui, "Deny").clicked() {
                                            aws_response = Some((request.id.clone(), None));
                                        }
                                        if snapshot.unlocked {
                                            if secondary_button(ui, "Grant read-only credentials")
                                                .clicked()
                                            {
                                                aws_response = Some((
                                                    request.id.clone(),
                                                    Some(AwsAccessLevel::ReadOnly),
                                                ));
                                            }
                                            if admin_button(ui, "Grant admin credentials").clicked()
                                            {
                                                aws_response = Some((
                                                    request.id.clone(),
                                                    Some(AwsAccessLevel::Admin),
                                                ));
                                            }
                                        } else if primary_button(ui, "Open SecretD to unlock")
                                            .clicked()
                                        {
                                            action = RequestDialogAction::OpenMain;
                                        }
                                    });
                                });
                        } else {
                            let request = snapshot
                                .pending
                                .first()
                                .expect("secret request was selected");
                            self.request_choices
                                .entry(request.id.clone())
                                .or_insert(RequestChoice { seconds: 300 });
                            Frame::new()
                                .fill(SURFACE)
                                .stroke(Stroke::new(
                                    1.0,
                                    if request.verified { LINE } else { AMBER },
                                ))
                                .corner_radius(14)
                                .inner_margin(Margin::same(18))
                                .show(ui, |ui| {
                                    request_heading(ui, request);
                                    ui.add_space(8.0);
                                    ui.label(
                                        RichText::new(format!(
                                            "{} · PID {}",
                                            request.origin.executable, request.origin.pid
                                        ))
                                        .color(MUTED),
                                    );
                                    egui::CollapsingHeader::new("Process tree").show(ui, |ui| {
                                        for (index, process) in
                                            request.process_tree.iter().enumerate()
                                        {
                                            ui.monospace(format!(
                                                "{}{} [{}]",
                                                "  ".repeat(index),
                                                process.command,
                                                process.pid
                                            ));
                                        }
                                    });
                                    ui.add_space(8.0);
                                    ui.horizontal_wrapped(|ui| {
                                        if danger_button(ui, "Deny").clicked() {
                                            response = Some((
                                                request.id.clone(),
                                                ApprovalDecision::Deny,
                                                None,
                                                GrantScope::Secret,
                                            ));
                                        }
                                        if snapshot.unlocked
                                            && secondary_button(ui, "Allow once").clicked()
                                        {
                                            response = Some((
                                                request.id.clone(),
                                                ApprovalDecision::Once,
                                                None,
                                                GrantScope::Secret,
                                            ));
                                        }
                                        if snapshot.unlocked && request.verified {
                                            let choice =
                                                self.request_choices.get_mut(&request.id).unwrap();
                                            egui::ComboBox::from_id_salt(format!(
                                                "ttl-{}",
                                                request.id
                                            ))
                                            .selected_text(duration_label(choice.seconds))
                                            .show_ui(
                                                ui,
                                                |ui| {
                                                    for seconds in [60, 300, 900, 3600] {
                                                        ui.selectable_value(
                                                            &mut choice.seconds,
                                                            seconds,
                                                            duration_label(seconds),
                                                        );
                                                    }
                                                },
                                            );
                                            if primary_button(ui, "Grant this secret").clicked() {
                                                response = Some((
                                                    request.id.clone(),
                                                    ApprovalDecision::Temporary,
                                                    Some(choice.seconds),
                                                    GrantScope::Secret,
                                                ));
                                            }
                                            if let Some(group) = &request.group {
                                                let label = group_grant_label(group);
                                                if primary_button(ui, &label).clicked() {
                                                    response = Some((
                                                        request.id.clone(),
                                                        ApprovalDecision::Temporary,
                                                        Some(choice.seconds),
                                                        GrantScope::Group,
                                                    ));
                                                }
                                            }
                                        } else if !snapshot.unlocked
                                            && primary_button(ui, "Open SecretD to unlock")
                                                .clicked()
                                        {
                                            action = RequestDialogAction::OpenMain;
                                        }
                                    });
                                });
                        }
                    });
            });
        if let Some((id, decision, seconds, scope)) = response {
            let result = self
                .controller
                .lock()
                .map_err(|_| "SecretD state is unavailable".to_string())
                .and_then(|mut controller| {
                    controller
                        .respond(&id, decision, seconds, scope)
                        .map_err(|error| error.to_string())
                });
            match result {
                Ok(()) => {
                    self.request_error = None;
                    action = RequestDialogAction::Close;
                }
                Err(error) => self.request_error = Some(error),
            }
            self.request_choices.remove(&id);
            self.refresh_state();
        }
        if let Some((id, level)) = aws_response {
            let result = self
                .controller
                .lock()
                .map_err(|_| "SecretD state is unavailable".to_string())
                .and_then(|mut controller| {
                    controller
                        .respond_aws(&id, level)
                        .map_err(|error| error.to_string())
                });
            match result {
                Ok(()) => {
                    self.request_error = None;
                    action = RequestDialogAction::Close;
                }
                Err(error) => self.request_error = Some(error),
            }
            self.refresh_state();
        }
        action
    }

    pub fn deny_oldest_request(&mut self) {
        let snapshot = self.snapshot();
        let deny_aws = match (snapshot.pending_aws.first(), snapshot.pending.first()) {
            (Some(aws), Some(secret)) => aws.requested_at <= secret.requested_at,
            (Some(_), None) => true,
            _ => false,
        };
        if deny_aws {
            if let Some(request) = snapshot.pending_aws.first()
                && let Ok(mut controller) = self.controller.lock()
            {
                let _ = controller.respond_aws(&request.id, None);
            }
        } else if let Some(request) = snapshot.pending.first()
            && let Ok(mut controller) = self.controller.lock()
        {
            let _ = controller.respond(
                &request.id,
                ApprovalDecision::Deny,
                None,
                GrantScope::Secret,
            );
            self.request_choices.remove(&request.id);
        }
        self.request_error = None;
        self.refresh_state();
    }

    fn grants_ui(&mut self, ui: &mut egui::Ui, snapshot: &AppSnapshot) {
        section_header(
            ui,
            "Active access",
            "AWS grants follow the requesting process. All grants disappear when SecretD exits or the vault locks.",
        );
        if snapshot.grants.is_empty() && snapshot.aws_grants.is_empty() {
            empty_state(ui, "No active grants");
            return;
        }
        let mut revoke = None;
        let mut revoke_aws = None;
        for grant in &snapshot.aws_grants {
            Frame::new()
                .fill(SURFACE)
                .stroke(Stroke::new(1.0, LINE))
                .corner_radius(14)
                .inner_margin(Margin::same(16))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "AWS {} · {} credentials",
                                    grant.profile,
                                    match grant.level {
                                        AwsAccessLevel::ReadOnly => "read-only",
                                        AwsAccessLevel::Admin => "admin",
                                    }
                                ))
                                .strong(),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "{} · PID {} · active for this process",
                                    grant.process.executable, grant.process.pid
                                ))
                                .small()
                                .color(MUTED),
                            );
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if danger_button(ui, "Revoke").clicked() {
                                revoke_aws = Some(grant.id.clone());
                            }
                        });
                    });
                });
            ui.add_space(8.0);
        }
        for grant in &snapshot.grants {
            Frame::new()
                .fill(SURFACE)
                .stroke(Stroke::new(1.0, LINE))
                .corner_radius(14)
                .inner_margin(Margin::same(16))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{} · {}",
                                    grant.resource,
                                    grant.scope.label()
                                ))
                                .strong(),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "{} · PID {} · expires in {}",
                                    grant.process.executable,
                                    grant.process.pid,
                                    duration_until(grant.expires_at)
                                ))
                                .small()
                                .color(MUTED),
                            );
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if danger_button(ui, "Revoke").clicked() {
                                revoke = Some(grant.id.clone());
                            }
                        });
                    });
                });
            ui.add_space(8.0);
        }
        if let Some(id) = revoke {
            if let Ok(mut controller) = self.controller.lock() {
                controller.revoke_grant(&id);
            }
            self.refresh_state();
        }
        if let Some(id) = revoke_aws {
            if let Ok(mut controller) = self.controller.lock() {
                controller.revoke_aws_grant(&id);
            }
            self.refresh_state();
        }
    }

    fn activity_ui(&mut self, ui: &mut egui::Ui, snapshot: &AppSnapshot) {
        section_header(
            ui,
            "Activity",
            "A memory-only record that is cleared when SecretD exits.",
        );
        if snapshot.audit.is_empty() {
            empty_state(ui, "No activity yet");
            return;
        }
        for entry in &snapshot.audit {
            Frame::new()
                .fill(SURFACE)
                .stroke(Stroke::new(1.0, LINE))
                .corner_radius(14)
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(audit_label(entry.action))
                                .strong()
                                .color(audit_color(entry.action)),
                        );
                        ui.label(RichText::new(&entry.secret).monospace().color(INK));
                        if let Some(resource) = &entry.resource {
                            ui.label(
                                RichText::new(format!(
                                    "{} · {resource}",
                                    entry.scope.map_or("", GrantScope::label)
                                ))
                                .small()
                                .color(MUTED),
                            );
                        }
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(duration_since(entry.occurred_at))
                                    .small()
                                    .color(MUTED),
                            );
                        });
                    });
                    ui.label(
                        RichText::new(format!(
                            "{} · PID {}",
                            entry.process.executable, entry.process.pid
                        ))
                        .small()
                        .color(MUTED),
                    );
                });
            ui.add_space(6.0);
        }
    }

    fn secret_editor(&mut self, context: &egui::Context) {
        let Some(draft) = &mut self.secret_draft else {
            return;
        };
        let mut save = false;
        let mut close = false;
        egui::Window::new(if draft.original_name.is_some() {
            "Edit credential"
        } else {
            "New credential"
        })
        .anchor(Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .collapsible(false)
        .resizable(false)
        .show(context, |ui| {
            ui.set_width(460.0);
            field_label(ui, "Name");
            singleline_field(
                ui,
                &mut draft.name,
                "service/account/token",
                false,
                f32::INFINITY,
            );
            field_label(ui, "Group (optional)");
            singleline_field(ui, &mut draft.group, "aws-read-only", false, f32::INFINITY);
            field_label(ui, "Value");
            ui.add(
                TextEdit::multiline(&mut *draft.value)
                    .desired_rows(6)
                    .frame(input_frame())
                    .desired_width(f32::INFINITY),
            );
            if let Some(error) = &self.form_error {
                error_banner(ui, error);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if primary_button(ui, "Save credential").clicked() {
                    save = true;
                }
                if secondary_button(ui, "Cancel").clicked() {
                    close = true;
                }
            });
        });
        if save {
            let result = self
                .controller
                .lock()
                .map_err(|_| "SecretD state is unavailable".to_string())
                .and_then(|mut controller| {
                    controller
                        .save_secret(
                            &draft.name,
                            &draft.value,
                            draft.original_name.as_deref(),
                            Some(&draft.group),
                        )
                        .map_err(|error| error.to_string())
                });
            match result {
                Ok(()) => {
                    close = true;
                    self.revealed = None;
                    self.toast("Saved securely", false);
                    self.refresh_state();
                }
                Err(error) => self.form_error = Some(error),
            }
        }
        if close {
            self.secret_draft = None;
            self.form_error = None;
        }
    }

    fn aws_editor(&mut self, context: &egui::Context) {
        let Some(draft) = &mut self.aws_draft else {
            return;
        };
        let mut save = false;
        let mut close = false;
        let title = match draft.step {
            AwsDraftStep::Connection => "Connect AWS IAM Identity Center",
            AwsDraftStep::Aliases => "Assign AWS profile aliases",
        };
        egui::Window::new(title)
            .anchor(Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(true)
            .default_width(650.0)
            .max_height(720.0)
            .show(context, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    match draft.step {
                        AwsDraftStep::Connection => {
                            ui.label(
                                RichText::new(
                                    "Step 1 of 2 · The portal connection and resulting login tokens are stored in the encrypted vault.",
                                )
                                .color(MUTED),
                            );
                            ui.add_space(8.0);
                            field_label(ui, "AWS access portal URL");
                            singleline_field(
                                ui,
                                &mut draft.start_url,
                                "https://example.awsapps.com/start",
                                false,
                                f32::INFINITY,
                            );
                            field_label(ui, "IAM Identity Center region");
                            singleline_field(
                                ui,
                                &mut draft.sso_region,
                                "ca-central-1",
                                false,
                                f32::INFINITY,
                            );
                        }
                        AwsDraftStep::Aliases => {
                            ui.label(
                                RichText::new(
                                    "Step 2 of 2 · Choose a local alias and the roles SecretD should offer for each discovered account. Clear an alias to omit that account.",
                                )
                                .color(MUTED),
                            );
                            ui.add_space(10.0);
                            for target in &mut draft.targets {
                                Frame::new()
                                    .fill(SURFACE_MUTED)
                                    .stroke(Stroke::new(1.0, LINE))
                                    .corner_radius(12)
                                    .inner_margin(Margin::same(14))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                RichText::new(if target.account_name.is_empty() {
                                                    "AWS account"
                                                } else {
                                                    &target.account_name
                                                })
                                                .strong(),
                                            );
                                            ui.label(
                                                RichText::new(&target.account_id)
                                                    .monospace()
                                                    .color(MUTED),
                                            );
                                        });
                                        if !target.email_address.is_empty() {
                                            ui.label(
                                                RichText::new(&target.email_address)
                                                    .small()
                                                    .color(MUTED),
                                            );
                                        }
                                        field_label(ui, "Local profile alias");
                                        singleline_field(
                                            ui,
                                            &mut target.profile,
                                            "prod",
                                            false,
                                            f32::INFINITY,
                                        );
                                        if !target.profile.trim().is_empty() {
                                            let roles = target.roles.clone();
                                            ui.columns(2, |columns| {
                                                role_picker(
                                                    &mut columns[0],
                                                    &target.account_id,
                                                    "Read-only role",
                                                    "ro",
                                                    &roles,
                                                    &mut target.read_only_role,
                                                );
                                                role_picker(
                                                    &mut columns[1],
                                                    &target.account_id,
                                                    "Admin role",
                                                    "admin",
                                                    &roles,
                                                    &mut target.admin_role,
                                                );
                                            });
                                        }
                                    });
                                ui.add_space(8.0);
                            }
                        }
                    }
                    if let Some(error) = &self.form_error {
                        ui.add_space(8.0);
                        error_banner(ui, error);
                    }
                    ui.add_space(12.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let label = match draft.step {
                            AwsDraftStep::Connection => "Save and sign in",
                            AwsDraftStep::Aliases => "Save profile aliases",
                        };
                        if primary_button(ui, label).clicked() {
                            save = true;
                        }
                        if secondary_button(ui, "Cancel").clicked() {
                            close = true;
                        }
                    });
                });
            });
        if save {
            let step = draft.step;
            let result = match step {
                AwsDraftStep::Connection => save_aws_connection(&self.controller, draft),
                AwsDraftStep::Aliases => save_aws_aliases(&self.controller, draft),
            };
            match result {
                Ok(()) => {
                    close = true;
                    if step == AwsDraftStep::Connection {
                        match begin_aws_login(
                            Arc::clone(&self.controller),
                            Arc::clone(&self.notify),
                        ) {
                            Ok(()) => {
                                self.toast("AWS connection saved; sign in to continue", false)
                            }
                            Err(error) => self.toast(error, true),
                        }
                    } else {
                        self.toast("AWS profile aliases saved", false);
                    }
                    self.refresh_state();
                }
                Err(error) => self.form_error = Some(error),
            }
        }
        if close {
            self.aws_draft = None;
            self.form_error = None;
        }
    }

    fn password_editor(&mut self, context: &egui::Context) {
        let Some(draft) = &mut self.password_draft else {
            return;
        };
        let mut save = false;
        let mut close = false;
        egui::Window::new("Change master password")
            .anchor(Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .show(context, |ui| {
                ui.set_width(400.0);
                ui.label(
                    RichText::new("Choose a new password for the encrypted local vault.")
                        .color(MUTED),
                );
                ui.add_space(8.0);
                field_label(ui, "New password");
                singleline_field(
                    ui,
                    &mut *draft.password,
                    "Enter a new password",
                    true,
                    f32::INFINITY,
                );
                field_label(ui, "Confirm password");
                singleline_field(
                    ui,
                    &mut *draft.confirmation,
                    "Enter it again",
                    true,
                    f32::INFINITY,
                );
                if let Some(error) = &self.form_error {
                    error_banner(ui, error);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if primary_button(ui, "Update password").clicked() {
                        save = true;
                    }
                    if secondary_button(ui, "Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if save {
            if *draft.password != *draft.confirmation {
                self.form_error = Some("Passwords do not match".into());
            } else {
                let result = self
                    .controller
                    .lock()
                    .map_err(|_| "SecretD state is unavailable".to_string())
                    .and_then(|mut controller| {
                        controller
                            .change_password(&draft.password)
                            .map_err(|error| error.to_string())
                    });
                match result {
                    Ok(()) => {
                        close = true;
                        self.toast("Password changed", false);
                    }
                    Err(error) => self.form_error = Some(error),
                }
            }
        }
        if close {
            self.password_draft = None;
            self.form_error = None;
        }
    }

    fn delete_dialog(&mut self, context: &egui::Context) {
        let Some(name) = self.delete_confirmation.clone() else {
            return;
        };
        let mut delete = false;
        let mut close = false;
        egui::Window::new("Delete credential?")
            .anchor(Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .show(context, |ui| {
                ui.label(format!(
                    "Permanently delete “{name}” from the encrypted vault?"
                ));
                ui.horizontal(|ui| {
                    if secondary_button(ui, "Cancel").clicked() {
                        close = true;
                    }
                    if danger_button(ui, "Delete").clicked() {
                        delete = true;
                    }
                });
            });
        if delete {
            let result = self
                .controller
                .lock()
                .map_err(|_| "SecretD state is unavailable".to_string())
                .and_then(|mut controller| {
                    controller
                        .delete_secret(&name)
                        .map_err(|error| error.to_string())
                });
            match result {
                Ok(()) => {
                    close = true;
                    self.revealed = None;
                    self.toast("Credential deleted", false);
                    self.refresh_state();
                }
                Err(error) => self.toast(error, true),
            }
        }
        if close {
            self.delete_confirmation = None;
        }
    }

    fn toast_ui(&mut self, context: &egui::Context) {
        let Some(toast) = &self.toast else {
            return;
        };
        if Instant::now() >= toast.expires_at {
            self.toast = None;
            return;
        }
        context.request_repaint_after(toast.expires_at - Instant::now());
        egui::Area::new(egui::Id::new("toast"))
            .anchor(Align2::CENTER_BOTTOM, egui::vec2(0.0, -20.0))
            .show(context, |ui| {
                Frame::new()
                    .fill(if toast.danger { RED } else { INK })
                    .corner_radius(10)
                    .inner_margin(Margin::symmetric(14, 9))
                    .show(ui, |ui| {
                        ui.label(RichText::new(&toast.message).color(Color32::WHITE));
                    });
            });
    }

    fn toast(&mut self, message: impl Into<String>, danger: bool) {
        self.toast = Some(Toast {
            message: message.into(),
            danger,
            expires_at: Instant::now() + Duration::from_millis(2_800),
        });
    }

    fn clear_sensitive_ui(&mut self) {
        self.auth_password.zeroize();
        self.auth_confirmation.zeroize();
        self.secret_draft = None;
        self.password_draft = None;
        self.aws_draft = None;
        self.revealed = None;
        self.form_error = None;
        self.request_error = None;
        self.auth_focus_requested = false;
    }
}

pub fn background_color() -> [f32; 4] {
    BACKGROUND.to_normalized_gamma_f32()
}

pub fn configure_style(context: &egui::Context) {
    let mut visuals = egui::Visuals::light();
    visuals.panel_fill = BACKGROUND;
    visuals.faint_bg_color = SURFACE_MUTED;
    visuals.extreme_bg_color = SURFACE_MUTED;
    visuals.text_edit_bg_color = Some(SURFACE);
    visuals.override_text_color = Some(INK);
    visuals.weak_text_color = Some(MUTED);
    visuals.window_fill = SURFACE;
    visuals.window_stroke = Stroke::new(1.0, LINE);
    visuals.window_corner_radius = CornerRadius::same(16);
    visuals.menu_corner_radius = CornerRadius::same(12);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(10);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, LINE_STRONG);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(10);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, GREEN);
    visuals.widgets.active.corner_radius = CornerRadius::same(10);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, GREEN);
    visuals.widgets.open.corner_radius = CornerRadius::same(10);
    visuals.widgets.open.bg_stroke = Stroke::new(1.0, GREEN);
    visuals.selection.bg_fill = Color32::from_rgb(189, 228, 210);
    visuals.selection.stroke = Stroke::new(1.5, GREEN);
    visuals.error_fg_color = RED;
    visuals.warn_fg_color = AMBER;
    context.set_visuals(visuals);
    context.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(14.0, 9.0);
        style.spacing.interact_size.y = 36.0;
        style.spacing.combo_width = 132.0;
        style.spacing.window_margin = Margin::same(22);
        style.text_styles.insert(
            egui::TextStyle::Heading,
            FontId::new(24.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Body,
            FontId::new(13.5, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            FontId::new(13.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Small,
            FontId::new(11.5, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Monospace,
            FontId::new(12.5, egui::FontFamily::Monospace),
        );
    });
}

fn section_header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(24.0).strong().color(INK));
    ui.label(RichText::new(subtitle).size(14.0).color(MUTED));
    ui.add_space(18.0);
}

fn empty_state(ui: &mut egui::Ui, title: &str) {
    let inner_width = (ui.available_width() - 64.0).max(0.0);
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(16)
        .inner_margin(Margin::same(32))
        .show(ui, |ui| {
            ui.set_min_width(inner_width);
            ui.vertical_centered(|ui| {
                ui.add_space(18.0);
                ui.label(RichText::new("•").size(28.0).color(GREEN));
                ui.label(RichText::new(title).size(18.0).strong().color(INK));
                ui.label(
                    RichText::new("Nothing needs your attention here right now.")
                        .size(13.0)
                        .color(MUTED),
                );
                ui.add_space(18.0);
            });
        });
}

fn field_label(ui: &mut egui::Ui, label: &str) {
    ui.label(RichText::new(label).size(12.0).strong().color(INK));
}

fn singleline_field(
    ui: &mut egui::Ui,
    text: &mut dyn egui::TextBuffer,
    hint: &str,
    password: bool,
    width: f32,
) -> egui::Response {
    let response = ui.add(
        TextEdit::singleline(text)
            .hint_text(hint)
            .password(password)
            .desired_width(width)
            .min_size(egui::vec2(0.0, 40.0))
            .frame(input_frame()),
    );
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect,
            10,
            Stroke::new(1.5, GREEN),
            egui::StrokeKind::Inside,
        );
    }
    response
}

fn input_frame() -> Frame {
    Frame::new()
        .fill(SURFACE_MUTED)
        .stroke(Stroke::new(1.0, LINE_STRONG))
        .corner_radius(10)
        .inner_margin(Margin::symmetric(12, 10))
}

fn brand_mark(ui: &mut egui::Ui) {
    Frame::new()
        .fill(GREEN_SOFT)
        .corner_radius(11)
        .inner_margin(Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.label(RichText::new("S").size(17.0).strong().color(GREEN));
        });
}

fn credential_mark(ui: &mut egui::Ui) {
    Frame::new()
        .fill(GREEN_SOFT)
        .corner_radius(10)
        .inner_margin(Margin::symmetric(9, 6))
        .show(ui, |ui| {
            ui.label(RichText::new("S").size(15.0).strong().color(GREEN));
        });
}

fn status_pill(ui: &mut egui::Ui, text: &str, foreground: Color32, background: Color32) {
    Frame::new()
        .fill(background)
        .corner_radius(20)
        .inner_margin(Margin::symmetric(10, 5))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 7.0;
                let (dot, _) = ui.allocate_exact_size(egui::vec2(7.0, 7.0), egui::Sense::hover());
                ui.painter().circle_filled(dot.center(), 3.5, foreground);
                ui.label(RichText::new(text).size(11.0).color(foreground));
            });
        });
}

fn error_banner(ui: &mut egui::Ui, error: &str) {
    let width = (ui.available_width() - 24.0).max(0.0);
    Frame::new()
        .fill(RED_SOFT)
        .stroke(Stroke::new(1.0, Color32::from_rgb(244, 204, 204)))
        .corner_radius(10)
        .inner_margin(Margin::symmetric(12, 9))
        .show(ui, |ui| {
            ui.set_min_width(width);
            ui.label(RichText::new(error).size(12.0).color(RED));
        });
}

fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
            .fill(GREEN)
            .stroke(Stroke::NONE)
            .corner_radius(10)
            .min_size(egui::vec2(0.0, 38.0)),
    )
}

fn full_primary_button(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    let width = ui.available_width();
    ui.add_enabled_ui(enabled, |ui| {
        ui.add_sized(
            [width, 42.0],
            egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
                .fill(GREEN)
                .stroke(Stroke::NONE)
                .corner_radius(10),
        )
    })
    .inner
}

fn secondary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(INK))
            .fill(SURFACE_MUTED)
            .stroke(Stroke::new(1.0, LINE))
            .corner_radius(10)
            .min_size(egui::vec2(0.0, 38.0)),
    )
}

fn danger_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(RED))
            .fill(RED_SOFT)
            .stroke(Stroke::new(1.0, Color32::from_rgb(246, 215, 215)))
            .corner_radius(10)
            .min_size(egui::vec2(0.0, 38.0)),
    )
}

fn admin_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
            .fill(AMBER)
            .stroke(Stroke::NONE)
            .corner_radius(10)
            .min_size(egui::vec2(0.0, 38.0)),
    )
}

fn nav_button(ui: &mut egui::Ui, view: &mut View, target: View, label: &str, count: usize) {
    let selected = *view == target;
    let button = egui::Button::new(
        RichText::new(format!("{label}   {count}"))
            .strong()
            .color(if selected { GREEN } else { MUTED }),
    )
    .fill(if selected {
        GREEN_SOFT
    } else {
        Color32::TRANSPARENT
    })
    .stroke(Stroke::NONE)
    .corner_radius(10)
    .min_size(egui::vec2(0.0, 36.0));
    if ui.add(button).clicked() {
        *view = target;
    }
}

fn request_heading(ui: &mut egui::Ui, request: &PendingRequest) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(&request.secret)
                .size(17.0)
                .strong()
                .color(INK),
        );
        if let Some(group) = &request.group {
            ui.label(RichText::new(group).small().color(GREEN));
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(if request.verified {
                    "Verified connection"
                } else {
                    "Unverified · allow once only"
                })
                .small()
                .color(if request.verified { GREEN } else { AMBER }),
            );
        });
    });
}

fn aws_request_heading(ui: &mut egui::Ui, request: &PendingAwsCredentialRequest) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("AWS profile {}", request.profile))
                .size(17.0)
                .strong()
                .color(INK),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(if request.verified {
                    "Verified connection"
                } else {
                    "Unverified · decision applies once"
                })
                .small()
                .color(if request.verified { GREEN } else { AMBER }),
            );
        });
    });
}

fn aws_connection_draft(snapshot: &AppSnapshot) -> AwsDraft {
    let connection = snapshot.aws.as_ref().map(|aws| &aws.configuration);
    AwsDraft {
        step: AwsDraftStep::Connection,
        start_url: connection.map_or_else(String::new, |value| value.start_url.clone()),
        sso_region: connection.map_or_else(String::new, |value| value.sso_region.clone()),
        targets: Vec::new(),
    }
}

fn aws_alias_draft(snapshot: &AppSnapshot) -> AwsDraft {
    let aws = snapshot
        .aws
        .as_ref()
        .expect("alias editor requires AWS discovery");
    let mut used_aliases = HashSet::new();
    let targets = aws
        .discovered_accounts
        .iter()
        .map(|account| {
            let existing = aws
                .configuration
                .targets
                .iter()
                .find(|target| target.account_id == account.account_id);
            let mut profile = existing.map_or_else(
                || suggested_alias(&account.account_name, &account.account_id),
                |target| target.profile.clone(),
            );
            if !used_aliases.insert(profile.clone()) {
                profile = format!("{}-{}", profile, &account.account_id[8..]);
                used_aliases.insert(profile.clone());
            }
            AwsTargetDraft {
                profile,
                account_id: account.account_id.clone(),
                account_name: account.account_name.clone(),
                email_address: account.email_address.clone(),
                roles: account.roles.clone(),
                read_only_role: existing.map_or_else(
                    || suggested_role(&account.roles, AwsAccessLevel::ReadOnly),
                    |target| target.read_only_role.clone(),
                ),
                admin_role: existing.map_or_else(
                    || suggested_role(&account.roles, AwsAccessLevel::Admin),
                    |target| target.admin_role.clone(),
                ),
                region: existing.map_or_else(String::new, |target| target.region.clone()),
            }
        })
        .collect();
    AwsDraft {
        step: AwsDraftStep::Aliases,
        start_url: aws.configuration.start_url.clone(),
        sso_region: aws.configuration.sso_region.clone(),
        targets,
    }
}

fn suggested_alias(account_name: &str, account_id: &str) -> String {
    let alias = account_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if alias.is_empty() {
        format!("account-{}", &account_id[8..])
    } else {
        alias
    }
}

fn suggested_role(roles: &[String], level: AwsAccessLevel) -> String {
    let keywords: &[&str] = match level {
        AwsAccessLevel::ReadOnly => &["readonly", "read-only", "viewer", "audit"],
        AwsAccessLevel::Admin => &["administrator", "admin"],
    };
    roles
        .iter()
        .find(|role| {
            let role = role.to_ascii_lowercase();
            keywords.iter().any(|keyword| role.contains(keyword))
        })
        .cloned()
        .unwrap_or_default()
}

fn role_picker(
    ui: &mut egui::Ui,
    account_id: &str,
    label: &str,
    kind: &str,
    roles: &[String],
    selected: &mut String,
) {
    field_label(ui, label);
    let width = finite_combo_width(ui.available_width(), ui.spacing().combo_width);
    egui::ComboBox::from_id_salt(("aws-role", account_id, kind))
        .selected_text(if selected.is_empty() {
            "Select role"
        } else {
            selected.as_str()
        })
        .width(width)
        .show_ui(ui, |ui| {
            for role in roles {
                ui.selectable_value(selected, role.clone(), role);
            }
        });
}

fn finite_combo_width(available_width: f32, fallback_width: f32) -> f32 {
    if available_width.is_finite() {
        available_width.max(120.0)
    } else {
        fallback_width.max(120.0)
    }
}

fn save_aws_connection(
    controller: &Arc<Mutex<Controller>>,
    draft: &AwsDraft,
) -> Result<(), String> {
    controller
        .lock()
        .map_err(|_| "SecretD state is unavailable".to_string())?
        .save_aws_connection(
            draft.start_url.trim().to_string(),
            draft.sso_region.trim().to_string(),
        )
        .map_err(|error| error.to_string())
}

fn save_aws_aliases(controller: &Arc<Mutex<Controller>>, draft: &AwsDraft) -> Result<(), String> {
    let selected: Vec<_> = draft
        .targets
        .iter()
        .filter(|target| !target.profile.trim().is_empty())
        .collect();
    if selected.is_empty() {
        return Err("Assign an alias to at least one AWS account".into());
    }
    for target in &selected {
        if !target.roles.contains(&target.read_only_role) {
            return Err(format!(
                "Select a read-only role for '{}'",
                target.profile.trim()
            ));
        }
        if !target.roles.contains(&target.admin_role) {
            return Err(format!(
                "Select an admin role for '{}'",
                target.profile.trim()
            ));
        }
    }
    let configuration = AwsConfiguration {
        start_url: draft.start_url.clone(),
        sso_region: draft.sso_region.clone(),
        targets: selected
            .into_iter()
            .map(|target| AwsTarget {
                profile: target.profile.trim().to_string(),
                account_id: target.account_id.clone(),
                read_only_role: target.read_only_role.clone(),
                admin_role: target.admin_role.clone(),
                region: target.region.clone(),
            })
            .collect(),
    };
    controller
        .lock()
        .map_err(|_| "SecretD state is unavailable".to_string())?
        .save_aws_configuration(configuration)
        .map_err(|error| error.to_string())
}

fn duration_label(seconds: u64) -> &'static str {
    match seconds {
        60 => "1 minute",
        300 => "5 minutes",
        900 => "15 minutes",
        3600 => "1 hour",
        _ => "Temporary",
    }
}

fn group_grant_label(group: &str) -> String {
    format!("Grant entire {group} group")
}

fn duration_until(timestamp: u64) -> String {
    let seconds = timestamp
        .saturating_sub(secretd::grants::now_millis())
        .div_ceil(1_000);
    if seconds >= 60 {
        format!("{}m", seconds.div_ceil(60))
    } else {
        format!("{seconds}s")
    }
}

fn duration_until_seconds(timestamp: u64) -> String {
    let seconds = timestamp.saturating_sub(secretd::aws::now_seconds());
    if seconds >= 60 {
        format!("{}m", seconds.div_ceil(60))
    } else {
        format!("{seconds}s")
    }
}

fn duration_since(timestamp: u64) -> String {
    let seconds = secretd::grants::now_millis()
        .saturating_sub(timestamp)
        .div_ceil(1_000);
    if seconds < 10 {
        "just now".into()
    } else if seconds < 60 {
        format!("{seconds}s ago")
    } else {
        format!("{}m ago", seconds / 60)
    }
}

fn audit_label(action: AuditAction) -> &'static str {
    match action {
        AuditAction::AllowedOnce => "Allowed once",
        AuditAction::GrantedTemporarily => "Access granted",
        AuditAction::AutoGranted => "Automatically released",
        AuditAction::Denied => "Request denied",
        AuditAction::TimedOut => "Request timed out",
        AuditAction::Revoked => "Access revoked",
    }
}

fn audit_color(action: AuditAction) -> Color32 {
    match action {
        AuditAction::Denied | AuditAction::TimedOut | AuditAction::Revoked => RED,
        AuditAction::AllowedOnce | AuditAction::GrantedTemporarily | AuditAction::AutoGranted => {
            GREEN
        }
    }
}

fn tray_status(snapshot: &AppSnapshot) -> TrayStatus {
    if snapshot.unlocked {
        TrayStatus::Unlocked
    } else {
        TrayStatus::Locked
    }
}

fn should_toggle_for_tray_click(
    button: tray_icon::MouseButton,
    state: tray_icon::MouseButtonState,
) -> bool {
    button == tray_icon::MouseButton::Left && state == tray_icon::MouseButtonState::Up
}

fn rebuild_tray_menu(menu: &Menu, snapshot: &AppSnapshot) -> tray_icon::menu::Result<()> {
    while menu.remove_at(0).is_some() {}
    let pending_count = snapshot.pending.len() + snapshot.pending_aws.len();
    if pending_count > 0 {
        menu.append(&MenuItem::new(
            format!(
                "{} access request{} pending",
                pending_count,
                if pending_count == 1 { "" } else { "s" }
            ),
            false,
            None,
        ))?;
        menu.append(&PredefinedMenuItem::separator())?;
    }
    menu.append(&MenuItem::with_id("show", "Open SecretD", true, None))?;
    menu.append(&MenuItem::with_id(
        "lock",
        "Lock vault",
        snapshot.unlocked,
        None,
    ))?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&MenuItem::with_id("quit", "Quit SecretD", true, None))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggles_only_for_a_completed_left_click() {
        assert!(should_toggle_for_tray_click(
            tray_icon::MouseButton::Left,
            tray_icon::MouseButtonState::Up
        ));
        assert!(!should_toggle_for_tray_click(
            tray_icon::MouseButton::Left,
            tray_icon::MouseButtonState::Down
        ));
        assert!(!should_toggle_for_tray_click(
            tray_icon::MouseButton::Right,
            tray_icon::MouseButtonState::Up
        ));
    }

    #[test]
    fn password_fields_have_a_visible_surface_and_border() {
        let context = egui::Context::default();
        configure_style(&context);
        let style = context.style_of(context.theme());
        let frame = input_frame();

        assert_eq!(style.visuals.text_edit_bg_color, Some(SURFACE));
        assert!(style.visuals.widgets.inactive.bg_stroke.width >= 1.0);
        assert_eq!(frame.fill, SURFACE_MUTED);
        assert!(frame.stroke.width >= 1.0);
        assert_ne!(frame.fill, style.visuals.window_fill);
    }

    #[test]
    fn group_grant_button_names_the_group() {
        assert_eq!(group_grant_label("aws-to"), "Grant entire aws-to group");
    }

    #[test]
    fn account_names_become_safe_profile_aliases() {
        assert_eq!(
            suggested_alias("Pre Production / Canada", "123456789012"),
            "pre-production-canada"
        );
        assert_eq!(suggested_alias("---", "123456789012"), "account-9012");
    }

    #[test]
    fn discovered_roles_are_suggested_by_access_level() {
        let roles = vec!["AdministratorAccess".into(), "ReadOnlyAccess".into()];
        assert_eq!(
            suggested_role(&roles, AwsAccessLevel::ReadOnly),
            "ReadOnlyAccess"
        );
        assert_eq!(
            suggested_role(&roles, AwsAccessLevel::Admin),
            "AdministratorAccess"
        );
        assert_eq!(
            suggested_role(&["PowerUser".into()], AwsAccessLevel::ReadOnly),
            ""
        );
    }

    #[test]
    fn aws_role_picker_width_is_always_finite() {
        assert_eq!(finite_combo_width(f32::INFINITY, 100.0), 120.0);
        assert_eq!(finite_combo_width(f32::NAN, 160.0), 160.0);
        assert_eq!(finite_combo_width(240.0, 100.0), 240.0);
    }
}
