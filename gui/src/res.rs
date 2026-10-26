const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
const RT_MANIFEST: u16 = 24;
const LANG_EN_US: u16 = 0x0409;
const MOVEABLE_PURE: u16 = 0x0030;

struct Image<'a> {
    entry: &'a [u8],
    data: &'a [u8],
}

fn read_ico(ico: &[u8]) -> Result<Vec<Image<'_>>, String> {
    let field = |at: usize, len: usize| {
        ico.get(at..at + len)
            .ok_or_else(|| format!("icon file ends at byte {}", ico.len()))
    };
    let header = field(0, 6)?;
    if header[..4] != [0, 0, 1, 0] {
        return Err("not an icon file".into());
    }
    let count = u16::from_le_bytes([header[4], header[5]]) as usize;
    if count == 0 {
        return Err("icon file has no images".into());
    }
    (0..count)
        .map(|i| {
            let entry = field(6 + 16 * i, 16)?;
            let word = |at: usize| {
                u32::from_le_bytes([entry[at], entry[at + 1], entry[at + 2], entry[at + 3]])
                    as usize
            };
            let data = field(word(12), word(8))?;
            Ok(Image { entry, data })
        })
        .collect()
}

fn push(out: &mut Vec<u8>, kind: u16, name: u16, flags: u16, data: &[u8]) {
    out.extend((data.len() as u32).to_le_bytes());
    out.extend(32u32.to_le_bytes());
    for word in [0xffff, kind, 0xffff, name] {
        out.extend(word.to_le_bytes());
    }
    out.extend(0u32.to_le_bytes());
    out.extend(flags.to_le_bytes());
    out.extend(if kind == 0 { 0 } else { LANG_EN_US }.to_le_bytes());
    out.extend([0; 8]);
    out.extend(data);
    out.resize(out.len().next_multiple_of(4), 0);
}

pub fn build(ico: &[u8], manifest: &[u8]) -> Result<Vec<u8>, String> {
    let images = read_ico(ico)?;
    let mut out = Vec::new();
    push(&mut out, 0, 0, 0, &[]);
    let mut group = vec![0, 0, 1, 0];
    group.extend((images.len() as u16).to_le_bytes());
    for (i, image) in images.iter().enumerate() {
        let id = i as u16 + 1;
        push(&mut out, RT_ICON, id, MOVEABLE_PURE, image.data);
        group.extend(&image.entry[..12]);
        group.extend(id.to_le_bytes());
    }
    push(&mut out, RT_GROUP_ICON, 1, MOVEABLE_PURE, &group);
    push(&mut out, RT_MANIFEST, 1, MOVEABLE_PURE, manifest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ico(images: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = vec![0, 0, 1, 0];
        out.extend((images.len() as u16).to_le_bytes());
        let mut offset = 6 + 16 * images.len() as u32;
        for (size, data) in images {
            out.extend([*size, *size, 0, 0]);
            out.extend(1u16.to_le_bytes());
            out.extend(32u16.to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend(offset.to_le_bytes());
            offset += data.len() as u32;
        }
        for (_, data) in images {
            out.extend(*data);
        }
        out
    }

    fn u16_at(b: &[u8], i: usize) -> u16 {
        u16::from_le_bytes([b[i], b[i + 1]])
    }

    fn u32_at(b: &[u8], i: usize) -> u32 {
        u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
    }

    fn entries(res: &[u8]) -> Vec<(u16, u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < res.len() {
            assert_eq!(at % 4, 0);
            let size = u32_at(res, at) as usize;
            let header = u32_at(res, at + 4) as usize;
            assert_eq!(header, 32);
            assert_eq!(u16_at(res, at + 8), 0xffff);
            assert_eq!(u16_at(res, at + 12), 0xffff);
            let (kind, name) = (u16_at(res, at + 10), u16_at(res, at + 14));
            out.push((kind, name, res[at + 32..at + 32 + size].to_vec()));
            at += (32 + size).next_multiple_of(4);
        }
        out
    }

    #[test]
    fn writes_icons_a_group_and_the_manifest() {
        let res = build(&ico(&[(16, b"abcde"), (0, b"xyz")]), b"<m/>").unwrap();
        let e = entries(&res);
        assert_eq!(e[0], (0, 0, vec![]));
        assert_eq!(e[1], (3, 1, b"abcde".to_vec()));
        assert_eq!(e[2], (3, 2, b"xyz".to_vec()));
        let mut group = vec![0, 0, 1, 0, 2, 0];
        group.extend([16, 16, 0, 0, 1, 0, 32, 0, 5, 0, 0, 0, 1, 0]);
        group.extend([0, 0, 0, 0, 1, 0, 32, 0, 3, 0, 0, 0, 2, 0]);
        assert_eq!(e[3], (14, 1, group));
        assert_eq!(e[4], (24, 1, b"<m/>".to_vec()));
        assert_eq!(e.len(), 5);
    }

    #[test]
    fn uses_us_english_for_every_resource() {
        let res = build(&ico(&[(16, b"a")]), b"m").unwrap();
        let mut at = 32;
        while at < res.len() {
            assert_eq!(u16_at(&res, at + 22), 0x0409);
            at += (32 + u32_at(&res, at) as usize).next_multiple_of(4);
        }
    }

    #[test]
    fn rejects_files_that_are_not_icons() {
        assert!(build(b"PNG", b"m").is_err());
        let mut cursor = ico(&[(16, b"a")]);
        cursor[2] = 2;
        assert!(build(&cursor, b"m").is_err());
        let mut short = ico(&[(16, b"abcd")]);
        short.truncate(short.len() - 1);
        assert!(build(&short, b"m").is_err());
        assert!(build(&ico(&[]), b"m").is_err());
    }

    #[test]
    fn embeds_every_image_of_the_app_icon() {
        let res = build(include_bytes!("../assets/gateinto.ico"), b"m").unwrap();
        let icons = entries(&res).iter().filter(|e| e.0 == 3).count();
        assert_eq!(icons, 8);
    }
}
