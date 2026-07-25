use tray_icon::Icon;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayStatus {
    Locked,
    Unlocked,
    Pending,
}

pub fn tray_icon(status: TrayStatus) -> Result<Icon, String> {
    let color = match status {
        TrayStatus::Locked => [126, 135, 130, 255],
        TrayStatus::Unlocked => [22, 155, 99, 255],
        TrayStatus::Pending => [216, 145, 34, 255],
    };
    const SIZE: u32 = 32;
    let mut rgba = vec![0; (SIZE * SIZE * 4) as usize];
    for y in 6_i32..28 {
        for x in 5_i32..27 {
            let dx = x - 16;
            let in_top = y < 17 && dx * dx + (y - 14) * (y - 14) <= 10 * 10;
            let in_body = (13..=25).contains(&y) && (7..=25).contains(&x);
            if !(in_top || in_body) {
                continue;
            }
            if (12..=20).contains(&x) && (10..=19).contains(&y) {
                continue;
            }
            let index = ((y as u32 * SIZE + x as u32) * 4) as usize;
            rgba[index..index + 4].copy_from_slice(&color);
        }
    }
    for y in 16_i32..23 {
        for x in 14_i32..18 {
            let index = ((y as u32 * SIZE + x as u32) * 4) as usize;
            rgba[index..index + 4].copy_from_slice(&color);
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE).map_err(|error| error.to_string())
}
