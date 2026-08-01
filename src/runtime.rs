use std::{
    error::Error,
    ffi::{CStr, CString, c_void},
    num::NonZeroU32,
    sync::Arc,
    time::Instant,
};

use egui_glow::EguiGlow;
use glow::HasContext;
use glutin::{
    config::ConfigTemplateBuilder,
    context::{
        ContextApi, ContextAttributesBuilder, NotCurrentGlContext, PossiblyCurrentContext,
        PossiblyCurrentGlContext,
    },
    display::{Display, GetGlDisplay, GlDisplay},
    prelude::GlSurface,
    surface::{Surface, SurfaceAttributesBuilder, SwapInterval, WindowSurface},
};
use tray_icon::{TrayIconEvent, menu::MenuEvent};
use winit::{
    application::ApplicationHandler,
    dpi::{LogicalSize, PhysicalPosition, PhysicalSize},
    event::{StartCause, WindowEvent},
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy},
    raw_window_handle::HasWindowHandle,
    window::{Window, WindowAttributes, WindowId, WindowLevel},
};

use crate::app::{AppEvent, RequestDialogAction, SecretDApp, background_color, configure_style};

#[derive(Clone, Copy)]
enum WindowKind {
    Main,
    Request,
}

const MAIN_WINDOW_SIZE: (f64, f64) = (1040.0, 700.0);
const REQUEST_WINDOW_SIZE: (f64, f64) = (620.0, 430.0);

pub fn run() -> Result<(), Box<dyn Error>> {
    let mut builder = EventLoop::<AppEvent>::with_user_event();
    #[cfg(target_os = "macos")]
    {
        use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
        builder.with_activation_policy(ActivationPolicy::Accessory);
    }
    let event_loop = builder.build()?;
    event_loop.set_control_flow(ControlFlow::Wait);
    let proxy = event_loop.create_proxy();
    let mut runtime = Runtime::new(proxy);
    event_loop.run_app(&mut runtime)?;
    Ok(())
}

struct Runtime {
    proxy: EventLoopProxy<AppEvent>,
    app: Option<SecretDApp>,
    ui: Option<UiRuntime>,
    request_ui: Option<UiRuntime>,
    repaint_at: Option<Instant>,
}

impl Runtime {
    fn new(proxy: EventLoopProxy<AppEvent>) -> Self {
        Self {
            proxy,
            app: None,
            ui: None,
            request_ui: None,
            repaint_at: None,
        }
    }

    fn open_ui(&mut self, event_loop: &ActiveEventLoop) {
        if let Some(ui) = &self.ui {
            ui.window().set_visible(true);
            ui.window().focus_window();
            ui.window().request_redraw();
            return;
        }
        match UiRuntime::new(event_loop, self.proxy.clone(), WindowKind::Main) {
            Ok(ui) => {
                self.ui = Some(ui);
                self.ui
                    .as_ref()
                    .expect("UI was just created")
                    .window()
                    .request_redraw();
            }
            Err(error) => eprintln!("Could not open SecretD window: {error}"),
        }
    }

    fn open_request_ui(&mut self, event_loop: &ActiveEventLoop) {
        if let Some(ui) = &self.request_ui {
            ui.window().set_visible(true);
            ui.window().focus_window();
            ui.window().request_redraw();
            return;
        }
        match UiRuntime::new(event_loop, self.proxy.clone(), WindowKind::Request) {
            Ok(ui) => {
                self.request_ui = Some(ui);
                self.request_ui
                    .as_ref()
                    .expect("request UI was just created")
                    .window()
                    .request_redraw();
            }
            Err(error) => eprintln!("Could not open SecretD access request: {error}"),
        }
    }

    fn close_ui(&mut self, event_loop: &ActiveEventLoop) {
        if let Some(app) = &mut self.app {
            app.on_ui_closed();
        }
        if let Some(ui) = self.ui.take() {
            ui.destroy();
        }
        self.repaint_at = None;
        event_loop.set_control_flow(ControlFlow::Wait);
    }

    fn close_request_ui(&mut self, event_loop: &ActiveEventLoop) {
        if let Some(ui) = self.request_ui.take() {
            ui.destroy();
        }
        self.repaint_at = None;
        event_loop.set_control_flow(ControlFlow::Wait);
    }

    fn request_repaint(&mut self, event_loop: &ActiveEventLoop, delay: std::time::Duration) {
        if delay.is_zero() {
            if let Some(ui) = &self.ui {
                ui.window().request_redraw();
            }
            if let Some(ui) = &self.request_ui {
                ui.window().request_redraw();
            }
            return;
        }
        if self.ui.is_none() && self.request_ui.is_none() {
            return;
        }
        let Some(deadline) = Instant::now().checked_add(delay) else {
            return;
        };
        if self.repaint_at.is_none_or(|current| deadline < current) {
            self.repaint_at = Some(deadline);
            event_loop.set_control_flow(ControlFlow::WaitUntil(deadline));
        }
    }

    fn redraw_main(&mut self, event_loop: &ActiveEventLoop) {
        let (Some(app), Some(ui)) = (&mut self.app, &mut self.ui) else {
            return;
        };
        if let Err(error) = ui.gl_window.make_current() {
            eprintln!("Could not activate SecretD OpenGL context: {error}");
            return;
        }
        let mut quit = false;
        ui.egui.run(ui.gl_window.window(), |root_ui| {
            quit = app.ui(root_ui);
        });
        let clear = background_color();
        unsafe {
            ui.gl.clear_color(clear[0], clear[1], clear[2], clear[3]);
            ui.gl.clear(glow::COLOR_BUFFER_BIT);
        }
        ui.egui.paint(ui.gl_window.window());
        if let Err(error) = ui.gl_window.swap_buffers() {
            eprintln!("Could not present SecretD window: {error}");
        }
        if !ui.shown {
            ui.gl_window.window().set_visible(true);
            ui.gl_window.window().focus_window();
            ui.shown = true;
        }
        if quit {
            event_loop.exit();
        }
    }

    fn redraw_request(&mut self, event_loop: &ActiveEventLoop) {
        let action = {
            let (Some(app), Some(ui)) = (&mut self.app, &mut self.request_ui) else {
                return;
            };
            if let Err(error) = ui.gl_window.make_current() {
                eprintln!("Could not activate SecretD request OpenGL context: {error}");
                return;
            }
            let mut action = RequestDialogAction::None;
            ui.egui.run(ui.gl_window.window(), |root_ui| {
                action = app.request_dialog_ui(root_ui);
            });
            let clear = background_color();
            unsafe {
                ui.gl.clear_color(clear[0], clear[1], clear[2], clear[3]);
                ui.gl.clear(glow::COLOR_BUFFER_BIT);
            }
            ui.egui.paint(ui.gl_window.window());
            if let Err(error) = ui.gl_window.swap_buffers() {
                eprintln!("Could not present SecretD access request: {error}");
            }
            if !ui.shown {
                ui.gl_window.window().set_visible(true);
                ui.gl_window.window().focus_window();
                ui.shown = true;
            }
            action
        };
        match action {
            RequestDialogAction::None => {}
            RequestDialogAction::Close => self.close_request_ui(event_loop),
            RequestDialogAction::OpenMain => self.open_ui(event_loop),
        }
    }
}

impl ApplicationHandler<AppEvent> for Runtime {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.app.is_none() {
            match SecretDApp::new(self.proxy.clone()) {
                Ok(app) => self.app = Some(app),
                Err(error) => {
                    eprintln!("Could not start SecretD: {error}");
                    event_loop.exit();
                }
            }
        }
        if std::env::args().any(|argument| argument == "--show") {
            self.open_ui(event_loop);
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: AppEvent) {
        match event {
            AppEvent::Show => self.open_ui(event_loop),
            AppEvent::Toggle => {
                if self.ui.is_some() {
                    self.close_ui(event_loop);
                } else {
                    self.open_ui(event_loop);
                }
            }
            AppEvent::Lock => {
                if let Some(app) = &mut self.app {
                    app.lock();
                }
                if let Some(ui) = &self.ui {
                    ui.window().request_redraw();
                }
            }
            AppEvent::StateChanged => {
                let (access_requests, login_in_progress) = if let Some(app) = &mut self.app {
                    app.refresh_state();
                    (app.has_access_requests(), app.aws_login_in_progress())
                } else {
                    (false, false)
                };
                if access_requests {
                    self.open_request_ui(event_loop);
                } else if self.request_ui.is_some() {
                    self.close_request_ui(event_loop);
                }
                if login_in_progress {
                    self.open_ui(event_loop);
                } else if let Some(ui) = &self.ui {
                    ui.window().request_redraw();
                }
            }
            AppEvent::Repaint(delay) => self.request_repaint(event_loop, delay),
            AppEvent::Quit => event_loop.exit(),
        }
    }

    fn new_events(&mut self, _event_loop: &ActiveEventLoop, cause: StartCause) {
        if matches!(cause, StartCause::ResumeTimeReached { .. }) {
            self.repaint_at = None;
            if let Some(ui) = &self.ui {
                ui.window().request_redraw();
            }
            if let Some(ui) = &self.request_ui {
                ui.window().request_redraw();
            }
        }
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        let is_main = self
            .ui
            .as_ref()
            .is_some_and(|ui| ui.window().id() == window_id);
        let is_request = self
            .request_ui
            .as_ref()
            .is_some_and(|ui| ui.window().id() == window_id);
        if !is_main && !is_request {
            return;
        }
        if is_request && matches!(event, WindowEvent::CloseRequested) {
            if let Some(app) = &mut self.app {
                app.deny_oldest_request();
            }
            self.close_request_ui(event_loop);
            return;
        }
        if is_request && matches!(event, WindowEvent::Destroyed) {
            self.request_ui = None;
            return;
        }
        if is_main && matches!(event, WindowEvent::CloseRequested | WindowEvent::Destroyed) {
            self.close_ui(event_loop);
            return;
        }
        if matches!(event, WindowEvent::RedrawRequested) {
            if is_request {
                self.redraw_request(event_loop);
            } else {
                self.redraw_main(event_loop);
            }
            return;
        }
        let ui = if is_request {
            self.request_ui
                .as_mut()
                .expect("request window event requires an open UI")
        } else {
            self.ui.as_mut().expect("window event requires an open UI")
        };
        if let WindowEvent::Resized(size) = &event {
            if let Err(error) = ui.gl_window.make_current() {
                eprintln!("Could not activate resized SecretD window: {error}");
                return;
            }
            ui.gl_window.resize(*size);
        }
        let response = ui.egui.on_window_event(ui.gl_window.window(), &event);
        if response.repaint {
            ui.egui.egui_ctx.request_repaint();
        }
    }

    fn suspended(&mut self, event_loop: &ActiveEventLoop) {
        self.close_request_ui(event_loop);
        self.close_ui(event_loop);
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        if let Some(ui) = self.ui.take() {
            ui.destroy();
        }
        if let Some(ui) = self.request_ui.take() {
            ui.destroy();
        }
        if let Some(app) = &mut self.app {
            app.shutdown();
        }
        MenuEvent::set_event_handler::<fn(MenuEvent)>(None);
        TrayIconEvent::set_event_handler::<fn(TrayIconEvent)>(None);
    }
}

struct UiRuntime {
    gl_window: GlutinWindowContext,
    gl: Arc<glow::Context>,
    egui: EguiGlow,
    shown: bool,
}

impl UiRuntime {
    fn new(
        event_loop: &ActiveEventLoop,
        event_proxy: EventLoopProxy<AppEvent>,
        kind: WindowKind,
    ) -> Result<Self, Box<dyn Error>> {
        let gl_window = unsafe { GlutinWindowContext::new(event_loop, kind)? };
        let gl = Arc::new(unsafe {
            glow::Context::from_loader_function(|name| {
                let name =
                    CString::new(name).expect("OpenGL symbol names cannot contain NUL bytes");
                gl_window.get_proc_address(&name)
            })
        });
        let egui = EguiGlow::new(event_loop, Arc::clone(&gl), None, None, true);
        configure_style(&egui.egui_ctx);
        egui.egui_ctx.set_request_repaint_callback(move |info| {
            let _ = event_proxy.send_event(AppEvent::Repaint(info.delay));
        });
        Ok(Self {
            gl_window,
            gl,
            egui,
            shown: false,
        })
    }

    fn window(&self) -> &Window {
        self.gl_window.window()
    }

    fn destroy(mut self) {
        if let Err(error) = self.gl_window.make_current() {
            eprintln!("Could not activate SecretD OpenGL context for cleanup: {error}");
        }
        self.egui.destroy();
        unsafe {
            self.gl.finish();
        }
        if let Err(error) = self.gl_window.make_not_current() {
            eprintln!("Could not detach SecretD OpenGL context: {error}");
        }
    }
}

struct GlutinWindowContext {
    window: Window,
    gl_context: PossiblyCurrentContext,
    gl_display: Display,
    gl_surface: Surface<WindowSurface>,
}

impl GlutinWindowContext {
    unsafe fn new(event_loop: &ActiveEventLoop, kind: WindowKind) -> Result<Self, Box<dyn Error>> {
        let window_attributes = match kind {
            WindowKind::Main => WindowAttributes::default()
                .with_resizable(true)
                .with_inner_size(LogicalSize::new(MAIN_WINDOW_SIZE.0, MAIN_WINDOW_SIZE.1))
                .with_min_inner_size(LogicalSize::new(720.0, 520.0))
                .with_title("SecretD"),
            WindowKind::Request => WindowAttributes::default()
                .with_resizable(false)
                .with_inner_size(LogicalSize::new(
                    REQUEST_WINDOW_SIZE.0,
                    REQUEST_WINDOW_SIZE.1,
                ))
                .with_title("SecretD Access Request")
                .with_window_level(WindowLevel::AlwaysOnTop),
        }
        .with_visible(false);
        let config_template = ConfigTemplateBuilder::new()
            .prefer_hardware_accelerated(None)
            .with_depth_size(0)
            .with_stencil_size(0)
            .with_transparency(false);
        let (window, gl_config) = glutin_winit::DisplayBuilder::new()
            .with_preference(glutin_winit::ApiPreference::FallbackEgl)
            .with_window_attributes(Some(window_attributes.clone()))
            .build(event_loop, config_template, |mut configs| {
                configs.next().expect("no compatible OpenGL configuration")
            })?;
        let gl_display = gl_config.display();
        let raw_window_handle = window
            .as_ref()
            .map(|window| window.window_handle().map(|handle| handle.as_raw()))
            .transpose()?;
        let context_attributes = ContextAttributesBuilder::new().build(raw_window_handle);
        let fallback_attributes = ContextAttributesBuilder::new()
            .with_context_api(ContextApi::Gles(None))
            .build(raw_window_handle);
        let not_current = unsafe {
            gl_display
                .create_context(&gl_config, &context_attributes)
                .or_else(|_| gl_display.create_context(&gl_config, &fallback_attributes))?
        };
        let window = match window {
            Some(window) => window,
            None => glutin_winit::finalize_window(event_loop, window_attributes, &gl_config)?,
        };
        center_window(&window);
        let size = window.inner_size();
        let surface_attributes = SurfaceAttributesBuilder::<WindowSurface>::new().build(
            window.window_handle()?.as_raw(),
            non_zero(size.width),
            non_zero(size.height),
        );
        let gl_surface =
            unsafe { gl_display.create_window_surface(&gl_config, &surface_attributes)? };
        let gl_context = not_current.make_current(&gl_surface)?;
        gl_surface.set_swap_interval(&gl_context, SwapInterval::Wait(NonZeroU32::MIN))?;
        Ok(Self {
            window,
            gl_context,
            gl_display,
            gl_surface,
        })
    }

    fn window(&self) -> &Window {
        &self.window
    }

    fn resize(&self, size: PhysicalSize<u32>) {
        self.gl_surface.resize(
            &self.gl_context,
            non_zero(size.width),
            non_zero(size.height),
        );
    }

    fn swap_buffers(&self) -> glutin::error::Result<()> {
        self.gl_surface.swap_buffers(&self.gl_context)
    }

    fn make_current(&self) -> glutin::error::Result<()> {
        self.gl_context.make_current(&self.gl_surface)
    }

    fn get_proc_address(&self, name: &CStr) -> *const c_void {
        self.gl_display.get_proc_address(name)
    }

    fn make_not_current(&self) -> glutin::error::Result<()> {
        self.gl_context.make_not_current_in_place()
    }
}

fn non_zero(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap_or(NonZeroU32::MIN)
}

fn center_window(window: &Window) {
    let Some(monitor) = window
        .current_monitor()
        .or_else(|| window.primary_monitor())
    else {
        return;
    };
    let monitor_position = monitor.position();
    let monitor_size = monitor.size();
    let window_size = window.outer_size();
    let x = monitor_position.x + (monitor_size.width.saturating_sub(window_size.width) / 2) as i32;
    let y =
        monitor_position.y + (monitor_size.height.saturating_sub(window_size.height) / 2) as i32;
    window.set_outer_position(PhysicalPosition::new(x, y));
}

#[cfg(test)]
mod tests {
    use super::{MAIN_WINDOW_SIZE, REQUEST_WINDOW_SIZE};

    #[test]
    fn request_window_is_compact_relative_to_the_main_window() {
        assert!(REQUEST_WINDOW_SIZE.0 < MAIN_WINDOW_SIZE.0);
        assert!(REQUEST_WINDOW_SIZE.1 < MAIN_WINDOW_SIZE.1);
    }
}
