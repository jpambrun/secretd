use std::io::Cursor;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use png::{BitDepth, ColorType, Decoder, Transformations};
use tray_icon::Icon;

const TRAY_ICON_PNG: &str = include_str!("../assets/tray-light.png.base64");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayStatus {
    Locked,
    Unlocked,
    Pending,
}

pub fn tray_icon(_status: TrayStatus) -> Result<Icon, String> {
    let (rgba, width, height) = decode_tray_icon()?;
    Icon::from_rgba(rgba, width, height).map_err(|error| error.to_string())
}

fn decode_tray_icon() -> Result<(Vec<u8>, u32, u32), String> {
    let encoded = STANDARD
        .decode(TRAY_ICON_PNG.trim())
        .map_err(|error| format!("invalid embedded tray icon: {error}"))?;
    let mut decoder = Decoder::new(Cursor::new(encoded));
    decoder.set_transformations(Transformations::EXPAND | Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .map_err(|error| format!("could not read embedded tray icon: {error}"))?;
    let mut rgba = vec![
        0;
        reader
            .output_buffer_size()
            .ok_or("embedded tray icon is too large")?
    ];
    let info = reader
        .next_frame(&mut rgba)
        .map_err(|error| format!("could not decode embedded tray icon: {error}"))?;
    if info.color_type != ColorType::Rgba || info.bit_depth != BitDepth::Eight {
        return Err("embedded tray icon must be an 8-bit RGBA PNG".to_owned());
    }
    rgba.truncate(info.buffer_size());
    Ok((rgba, info.width, info.height))
}

#[cfg(test)]
mod tests {
    use super::decode_tray_icon;

    #[test]
    fn embeds_the_original_typescript_tray_icon() {
        let (rgba, width, height) = decode_tray_icon().expect("tray icon should decode");

        assert_eq!((width, height), (44, 44));
        assert_eq!(rgba.len(), 44 * 44 * 4);
    }
}
