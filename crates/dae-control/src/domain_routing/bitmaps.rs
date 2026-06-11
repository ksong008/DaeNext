use super::*;
pub(super) fn merge_owner_bitmaps(owners: &HashMap<String, [u32; 32]>) -> [u32; 32] {
    let mut merged = [0; 32];
    for bitmap in owners.values() {
        or_bitmap(&mut merged, bitmap);
    }
    merged
}

pub(super) fn or_bitmap(dst: &mut [u32; 32], src: &[u32; 32]) {
    for (dst, src) in dst.iter_mut().zip(src.iter()) {
        *dst |= *src;
    }
}
