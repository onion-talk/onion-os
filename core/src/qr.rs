//! Offline Vector QR Code Generator (`POST /api/qr/svg`)
//! Renders crisp standalone `<svg ...>...</svg>` documents in pure Rust with zero external requests.

use qrcode::render::svg;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};

pub const MAX_QR_TEXT_LEN: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrSvgResponse {
    pub svg: String,
}

pub fn render_qr_svg(text: &str) -> Result<String, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("QR payload text cannot be empty".into());
    }
    if trimmed.len() > MAX_QR_TEXT_LEN || trimmed.chars().count() > MAX_QR_TEXT_LEN {
        return Err(format!(
            "QR payload exceeds maximum length ({MAX_QR_TEXT_LEN} chars)"
        ));
    }

    let code = QrCode::new(trimmed.as_bytes())
        .map_err(|e| format!("QR matrix encoding error: {e}"))?;

    let raw_svg = code
        .render()
        .min_dimensions(240, 240)
        .dark_color(svg::Color("#111318"))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build();

    let clean_svg = match raw_svg.find("<svg") {
        Some(idx) => raw_svg[idx..].trim().to_owned(),
        None => raw_svg.trim().to_owned(),
    };

    Ok(clean_svg)
}
