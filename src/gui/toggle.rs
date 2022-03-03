use eframe::egui;
use eframe::egui::Color32;

/// Here is the same code again, but a bit more compact:
pub fn toggle_ui_compact(ui: &mut egui::Ui, on: &mut bool) -> egui::Response {
    let desired_size = ui.spacing().interact_size.y * egui::vec2(2.0, 1.0);
    let (rect, mut response) = ui.allocate_exact_size(desired_size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    response.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Checkbox, *on, ""));

    if ui.is_rect_visible(rect) {
        let how_on = ui.ctx().animate_bool(response.id, *on);
        let visuals = ui.style().interact_selectable(&response, *on);
        let rect = rect.expand(visuals.expansion);
        let radius = 0.5 * rect.height();
        let selected_color = Color32::from_rgb(0x20, 0xaf, 0x24);
        if *on {
            ui.painter()
                .rect(rect, radius, selected_color, visuals.bg_stroke);
        }
        else {
            ui.painter()
                .rect(rect, radius, visuals.bg_fill, visuals.bg_stroke);
        }
        let circle_x = egui::lerp((rect.left() + radius)..=(rect.right() - radius), how_on);
        let center = egui::pos2(circle_x, rect.center().y);
        if *on {
            ui.painter()
                .circle(center, 0.75 * radius, selected_color, visuals.fg_stroke);
        } else {
            ui.painter()
                .circle(center, 0.75 * radius, visuals.bg_fill, visuals.fg_stroke);
        }
    }

    response
}