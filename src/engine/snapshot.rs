//! 快照解析：外层(#[magic 4B][length 8B][kind 8B][hash 32B][features\0]) + 流头
//! + cluster alloc 段遍历。
//!
//! alloc 骨架（五种 alloc kind + class/instance/library/function 特殊段）属于
//! 引擎固定部分；哪些 cid 属于哪一类、typed-data 元素宽度等由 SDK Profile 驱动。

use crate::engine::varint::Reader;
use crate::profile::SdkProfile;
use std::collections::BTreeMap;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Header {
    pub map: HashMap<String, u64>,
}

impl Header {
    pub fn get(&self, name: &str) -> u64 {
        *self.map.get(name).unwrap_or(&0)
    }
}

#[derive(Debug, Clone)]
pub struct ClusterMeta {
    pub cid: u64,
    pub canonical: bool,
    pub start_ref: u64,
    pub count: u64,
    pub kind: String,
    /// var 类：每对象长度
    pub lengths: Vec<u64>,
    /// rodata 类：绝对 running_offset
    pub offsets: Vec<u64>,
    /// code 类：deferred 对象数（alloc 从 count 中并入）
    pub deferred: u64,
    /// instance 类
    pub next_field_offset_in_words: i64,
    pub instance_size_in_words: i64,
    /// class 类：预定义数 + 显式 class_ids
    pub predefined_count: u64,
    pub class_ids: Vec<i64>,
}

pub type PResult<T> = Result<T, String>;

/// 快照外层版本指纹：kind + 32B 版本 hash + features 串。
/// 读取完全不依赖 SDK Profile（固定偏移），供自动识别 hash 精确命中。
#[derive(Debug, Clone)]
pub struct SnapshotFingerprint {
    pub kind: i64,
    pub version_hash: String,
    pub features: String,
}

/// 读取快照外层的版本指纹。外层布局：magic(4B) + length(8B) + kind(8B)
/// + version hash(32B) + features(\0 结尾)。
pub fn read_fingerprint(data: &[u8], base: usize) -> Option<SnapshotFingerprint> {
    if base + 60 > data.len() || data.get(base..base + 4)? != [0xf5, 0xf5, 0xdc, 0xdc] {
        return None;
    }
    let kind = i64::from_le_bytes(data.get(base + 12..base + 20)?.try_into().ok()?);
    if !(1..=8).contains(&kind) {
        return None;
    }
    let hb = data.get(base + 20..base + 52)?;
    if !hb.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return None;
    }
    let version_hash = String::from_utf8(hb.to_vec()).ok()?;
    let feat_end = data[base + 52..]
        .iter()
        .take(4096)
        .position(|&b| b == 0)
        .map(|p| base + 52 + p)?;
    let features = String::from_utf8_lossy(&data[base + 52..feat_end]).into_owned();
    Some(SnapshotFingerprint { kind, version_hash, features })
}

/// Reader 的 VarintError 在解析层统一折叠为字符串错误
impl From<crate::engine::varint::VarintError> for String {
    fn from(e: crate::engine::varint::VarintError) -> String {
        format!("变长整型读取错误: {e:?}")
    }
}

#[derive(Debug, Clone)]
pub enum FieldVal {
    Unboxed { v: u64, slot: i64 },
    Ref { v: u64, slot: i64 },
}

pub struct Snapshot<'a> {
    pub data: &'a [u8],
    pub base: usize,
    pub length_field: i64,
    pub length: i64,
    pub kind: i64,
    pub data_image: usize,
    pub hdr: Header,
    pub clusters: Vec<ClusterMeta>,
    pub alloc_end: usize,
    /// ref → cid 的二分索引（start,end,cid），解析后构建；clusters 天然按 start_ref 升序
    cid_index: Vec<(u64, u64, u64)>,
    // ----- alloc 阶段产物 -----
    pub mint_values: HashMap<u64, i64>,
    // ----- fill 阶段产物 -----
    /// 值可为 None：decode_string_at 失败的占位（与参考实现一致）
    pub strings: BTreeMap<u64, Option<String>>,
    pub classes: BTreeMap<u64, ClassRec>,
    pub libraries: BTreeMap<u64, LibraryRec>,
    pub functions: BTreeMap<u64, FunctionRec>,
    pub patch_classes: HashMap<u64, u64>,
    pub type_cids: HashMap<u64, u64>,
    pub instance_fields: BTreeMap<u64, (u64, Vec<FieldVal>)>,
    pub array_elements: HashMap<u64, (u64, Vec<u64>)>,
    pub map_data: HashMap<u64, (u64, u64, u64)>,
    pub objectpool_entries: Option<Vec<PoolEntry>>,
    pub payload_infos: Option<Vec<u64>>,
    pub code_start_ref: Option<u64>,
    /// ≤2.16（bare instructions）：Code fill 的 text-offset delta 逐对象累加和，
    /// 顺序 = 非 deferred code 对象的填充顺序（对应 SDK previous_text_offset_）。
    /// entry_point = instr_base + text_offsets[i] (+polymorphic 偏移)。
    pub text_offsets: Option<Vec<u64>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClassRec {
    pub name_ref: u64,
    pub library_ref: u64,
    pub class_id: i64,
    pub super_type_ref: u64,
    pub next_field_off: i64,
    pub type_arg_off: i64,
    pub field_bitmap: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FunctionRec {
    pub name_ref: u64,
    pub owner_ref: u64,
    pub code_index: u64,
    pub kind_tag: i64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LibraryRec {
    pub name_ref: u64,
    pub url_ref: u64,
}

/// ObjectPool entry（pp.txt 用）：(bits, typ, value)
#[derive(Debug, Clone, PartialEq)]
pub struct PoolEntry {
    pub bits: u64,
    pub typ: String, // "stub" | "obj" | "imm" | "native"
    pub value: Option<i64>,
}

impl<'a> Snapshot<'a> {
    /// 3.13+ 单快照模式：无独立 VM 快照——空表占位（对象全在 ISO 快照）
    pub fn stub(profile: &SdkProfile, data: &'a [u8]) -> Snapshot<'a> {
        let _ = profile;
        Snapshot {
            data,
            base: 0,
            length_field: 0,
            length: 0,
            kind: 0,
            data_image: 0,
            hdr: Header { map: HashMap::new() },
            clusters: Vec::new(),
            alloc_end: 0,
            cid_index: Vec::new(),
            mint_values: HashMap::new(),
            strings: BTreeMap::new(),
            classes: BTreeMap::new(),
            libraries: BTreeMap::new(),
            functions: BTreeMap::new(),
            patch_classes: HashMap::new(),
            type_cids: HashMap::new(),
            instance_fields: BTreeMap::new(),
            array_elements: HashMap::new(),
            map_data: HashMap::new(),
            objectpool_entries: None,
            payload_infos: None,
            code_start_ref: None,
            text_offsets: None,
        }
    }

    /// 解析快照外层 + 流头 + alloc 段。base = 快照起点的文件偏移。
    pub fn parse(
        profile: &SdkProfile,
        data: &'a [u8],
        base: usize,
        mut out: Option<&mut Vec<String>>,
    ) -> PResult<Snapshot<'a>> {
        if base + 20 > data.len() {
            return Err(format!("快照 @ {base:#x} 越界（文件太小?）"));
        }
        let mut r = Reader::new(data);
        // 外层：magic(4B，跳过) + length(i64 @ +4) + kind(i64 @ +12)
        r.pos = base + 4;
        let length_field = r.read_i64_le()?;
        let length = length_field + 4;
        let kind = r.read_i64_le()?;
        // hash 32B，跳过；找 features \0（从 +52 起）
        let feat_end = data[base + 52..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| base + 52 + p)
            .ok_or("features 串未终止：快照起点可能有误".to_string())?;
        let data_image = base + (((length as u64 + profile.object_start_alignment - 1)
            / profile.object_start_alignment)
            * profile.object_start_alignment) as usize;

        let mut hdr = HashMap::new();
        r.pos = feat_end + 1;
        for f in &profile.header_fields {
            let v = if f.is_signed() {
                r.read_signed()? as u64
            } else {
                r.read_unsigned()?
            };
            hdr.insert(f.name().to_string(), v);
        }
        let hdr = Header { map: hdr };

        let mut snap = Snapshot {
            data,
            base,
            length_field,
            length,
            kind,
            data_image,
            hdr,
            clusters: Vec::new(),
            alloc_end: 0,
            mint_values: HashMap::new(),
            strings: BTreeMap::new(),
            classes: BTreeMap::new(),
            libraries: BTreeMap::new(),
            functions: BTreeMap::new(),
            patch_classes: HashMap::new(),
            type_cids: HashMap::new(),
            instance_fields: BTreeMap::new(),
            array_elements: HashMap::new(),
            map_data: HashMap::new(),
            objectpool_entries: None,
            payload_infos: None,
            code_start_ref: None,
            text_offsets: None,
            cid_index: Vec::new(),
        };

        snap.parse_alloc(profile, &mut r, out.as_deref_mut())?;
        snap.alloc_end = r.pos;
        snap.build_cid_index();
        Ok(snap)
    }

    /// cluster 流 alloc 段（参考 dart_aot_full.py _parse_alloc）
    fn parse_alloc(
        &mut self,
        profile: &SdkProfile,
        r: &mut Reader<'a>,
        mut out: Option<&mut Vec<String>>,
    ) -> PResult<()> {
        let num_base = self.hdr.get("num_base_objects");
        let num_objects = self.hdr.get("num_objects");
        // 2.12-2.13：头部有独立的 num_canonical_clusters，簇总 = 两者之和
        // （canonical 簇在前，之后是常规簇；陈旧版本该字段缺失 → 0 不影响）
        let num_canonical = self.hdr.get("num_canonical_clusters") as usize;
        let num_clusters = (self.hdr.get("num_clusters") + self.hdr.get("num_canonical_clusters")) as usize;
        let mut next_ref = num_base + 1;
        let mut warn = |m: String| {
            if let Some(v) = out.as_deref_mut() {
                v.push(m);
            }
        };

        for i in 0..num_clusters {
            if std::env::var("DART_AOT_DEBUG_CLUSTERS").is_ok() {
                let p0 = r.pos;
                let b = &r.data.get(p0..p0 + 16.min(r.data.len().saturating_sub(p0))).unwrap_or(&[]);
                eprintln!("[dbg-head] cluster {i} pos=0x{p0:x} base=0x{:x} bytes={:02x?}", self.base, b);
            }
            let head = r.read_signed()?;
            let (cid, canonical) = if profile.format.cluster_header == "cid_tags" {
                // 3.6+：cluster 头 = 完整对象 tags（20-bit class id 位域 + canonical bit1）
                let tags = head as u64;
                ((tags >> profile.tagging.cid_tag_pos as u64) & profile.tagging.cid_tag_mask,
                 (tags >> 1) & 1 != 0)
            } else if profile.format.cluster_header == "raw_cid" {
                // 2.10–2.14：cluster 头 = 裸 cid（无 canonical 位）。2.13/2.14 的
                // canonical 簇按位置判定 = 前 num_canonical_clusters 个（官方
                // Deserialize 先读 canonical_clusters_ 数组实证）；≤2.12 该计数为 0。
                (head as u64, i < num_canonical)
            } else {
                ((head >> 1) as u64, head & 1 != 0)
            };
            if cid > 60000 {
                warn(format!("!!! drift cluster {i} cid={cid}"));
                break;
            }
            if profile.alloc.cid_only_alloc_cids.contains(&cid) {
                // alloc 仅 cid（无 count）：2.13 WeakSerializationReference
                self.clusters.push(ClusterMeta {
                    cid,
                    canonical,
                    start_ref: next_ref,
                    count: 0,
                    kind: profile.alloc_kind(cid).to_string(),
                    lengths: Vec::new(),
                    offsets: Vec::new(),
                    deferred: 0,
                    next_field_offset_in_words: 0,
                    instance_size_in_words: 0,
                    predefined_count: 0,
                    class_ids: Vec::new(),
                });
                continue;
            }
            let count = r.read_unsigned()?;
            let kind = profile.alloc_kind(cid).to_string();
            let mut meta = ClusterMeta {
                cid,
                canonical,
                start_ref: next_ref,
                count,
                kind: kind.clone(),
                lengths: Vec::new(),
                offsets: Vec::new(),
                deferred: 0,
                next_field_offset_in_words: 0,
                instance_size_in_words: 0,
                predefined_count: 0,
                class_ids: Vec::new(),
            };
            match kind.as_str() {
                "var" => {
                    for _ in 0..count {
                        meta.lengths.push(r.read_unsigned()?);
                    }
                    if std::env::var("DART_AOT_DEBUG_CLUSTERS").is_ok() && cid == 87 {
                        eprintln!("[dbg-var87] count={count} lengths 前6={:?} pos={}", 
                            &meta.lengths[..meta.lengths.len().min(6)], r.pos);
                    }
                }
                "rodata" => {
                    let mut running: u64 = 0;
                    for _ in 0..count {
                        let delta = r.read_unsigned()?;
                        running += delta << profile.tagging.object_alignment_log2;
                        meta.offsets.push(running);
                    }
                }
                "mint" => {
                    for k in 0..count {
                        let mv = r.read_signed()?;
                        self.mint_values.insert(next_ref + k, mv);
                    }
                }
                "code" => {
                    if profile.format.code_alloc == "count_only" {
                        // ≤2.9：Code alloc 仅 count
                    } else if profile.format.code_alloc == "deferred_only" {
                        // 2.10-2.14 系：count + deferred_count（无逐对象 state_bits）。
                        // fill 的 pre/post 分段边界 = 非 deferred 对象数
                        meta.predefined_count = count;
                        let deferred = r.read_unsigned()?;
                        meta.deferred = deferred;
                        meta.count += deferred;
                    } else {
                        for _ in 0..count {
                            let _ = r.read_signed()?; // state_bits int32
                        }
                        let deferred = r.read_unsigned()?;
                        for _ in 0..deferred {
                            let _ = r.read_signed()?;
                        }
                        meta.deferred = deferred;
                        meta.count += deferred;
                    }
                }
                "instance" => {
                    meta.next_field_offset_in_words = r.read_signed()?;
                    if profile.format.instance_alloc_nfo_only {
                        meta.instance_size_in_words = 0; // 2.10：无 isize 读（样本实证）
                    } else {
                        meta.instance_size_in_words = r.read_signed()?;
                    }
                }
                "class" => {
                    // 3.13+：Class alloc 为 ReadAllocFixedSize（无 pre 段）
                    if profile.format.class_alloc == "fixed" {
                        // count 已在簇头读取，无需额外
                    } else {
                        meta.predefined_count = count;
                        for _ in 0..count {
                            meta.class_ids.push(r.read_signed()?);
                        }
                        let count2 = r.read_unsigned()?;
                        meta.count += count2;
                        if std::env::var("DART_AOT_DEBUG_CLASSIDS").is_ok() {
                            eprintln!("[dbg-classids] {} 个 pre-id，前 8 个: {:?}", meta.class_ids.len(), &meta.class_ids[..meta.class_ids.len().min(8)]);
                        }
                    }
                }
                // ≤2.10：Type / TypeParameter 簇双段双计数（canonical 段 + 常规段）
                "fixed" if profile.format.type_dual_count
                    && (cid == profile.alloc.type_cid
                        || cid == profile.alloc.type_parameter_cid) => {
                    let count2 = r.read_unsigned()?;
                    meta.count += count2;
                }
                _ => {} // library / function / fixed：无额外
            }
            if std::env::var("DART_AOT_DEBUG_CLUSTERS").is_ok() && i < 200 {
                if kind == "instance" {
                    eprintln!("[dbg-inst] #{i} cid={cid} count={}->{} nfo={} isize={}",
                        count, meta.count, meta.next_field_offset_in_words, meta.instance_size_in_words);
                }
                eprintln!("[dbg-cluster] #{i} @+{} cid={cid} canonical={} count={} kind={}",
                    r.pos, canonical, count, kind);
            }
            if canonical && profile.alloc.canonical_table_cids.contains(&cid) {
                // canonical 表：table_length + [first_element] + gaps。
                // first_element 仅「子集型」表写入（2.13/2.14 = 只有 Type 簇，
                // kAllCanonicalObjectsAreIncludedIntoSet=false；2.15+ 全部簇都写）。
                let _table_length = r.read_unsigned()?;
                let first_element = if profile.alloc.canonical_subset_table_cids.contains(&cid) {
                    r.read_unsigned()?
                } else {
                    0
                };
                for _ in 0..meta.count.saturating_sub(first_element) {
                    let _ = r.read_unsigned()?;
                }
            }
            next_ref += meta.count; // class(±count2)/code(±deferred) 调整后的对象数
            self.clusters.push(meta);
        }
        let total = next_ref - 1;
        if total != num_objects {
            warn(format!(
                "!! alloc mismatch: got {total} want {num_objects}"
            ));
        }
        Ok(())
    }

    /// 参考实现 decode_string_at：off 为 data_image 相对偏移。
    /// tags 8B + length(Smi) 8B + chars。cid=(tags>>12)&0xfffff。
    pub fn decode_string_at(&self, profile: &SdkProfile, off: u64) -> Option<String> {
        let d = self.data;
        let a = self.data_image + off as usize;
        if a + 16 > d.len() {
            return None;
        }
        let tags = u64::from_le_bytes(d[a..a + 8].try_into().ok()?);
        let cid = (tags >> profile.tagging.cid_tag_pos as u64) & profile.tagging.cid_tag_mask;
        let ln = (u64::from_le_bytes(d[a + 8..a + 16].try_into().ok()?) >> 1) as usize;
        if ln > 10000 {
            return None;
        }
        if cid == profile.alloc.one_byte_string_cid {
            let end = a + 16 + ln;
            if end > d.len() {
                return None;
            }
            let bytes = &d[a + 16..end];
            if bytes.is_ascii() {
                // SAFETY: is_ascii 成立 → 全部 < 0x80，必为合法 UTF-8
                return Some(unsafe { String::from_utf8_unchecked(bytes.to_vec()) });
            }
            // latin1：字节码点直接映射
            Some(bytes.iter().map(|&b| b as char).collect())
        } else if cid == profile.alloc.two_byte_string_cid {
            let end = a + 16 + ln * 2;
            if end > d.len() {
                return None;
            }
            let u16s: Vec<u16> = d[a + 16..end]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&u16s))
        } else {
            None
        }
    }

    /// ref → cid：二分查找（原线性扫 cluster 表，pp/objs 大量调用下是主热点）
    #[inline]
    pub fn cid_at(&self, ref_: u64) -> Option<u64> {
        let idx = self.cid_index.partition_point(|&(start, _end, _cid)| start <= ref_);
        if idx == 0 {
            return None;
        }
        let (start, end, cid) = self.cid_index[idx - 1];
        if start <= ref_ && ref_ < end {
            Some(cid)
        } else {
            None
        }
    }

    fn build_cid_index(&mut self) {
        self.cid_index.clear();
        for c in &self.clusters {
            self.cid_index.push((c.start_ref, c.start_ref + c.count, c.cid));
        }
        // clusters 按生成顺序 start_ref 单调不减；防御性排序保不变量
        if self.cid_index.windows(2).any(|w| w[0].0 > w[1].0) {
            self.cid_index.sort_unstable_by_key(|e| e.0);
        }
    }

    /// 指令表解码：InstructionsTable 的 Data 藏在 instructions_table_rodata_offset
    /// 处 OneByteString 的 data 区（+16）。返回 (first_entry_with_code, pc_offsets)。
    pub fn has_instructions_offset(&self) -> bool {
        self.hdr.map.contains_key("instructions_table_rodata_offset")
            && self.hdr.get("instructions_table_rodata_offset") > 0
    }

    pub fn decode_instructions_table(&self) -> (u64, Vec<u64>) {
        let d = self.data;
        let Some(&rodata_off) = self.hdr.map.get("instructions_table_rodata_offset") else {
            // 2.15：指令表在 AOT image 而非快照流（header 无该字段）
            return (0, Vec::new());
        };
        let a = self.data_image + rodata_off as usize;
        if a + 32 > d.len() {
            return (0, Vec::new());
        }
        let ds = a + 16;
        let u32at = |p: usize| u32::from_le_bytes(d[p..p + 4].try_into().unwrap_or([0; 4])) as u64;
        let _canonical_off = u32at(ds);
        let length = u32at(ds + 4);
        let first_entry_with_code = u32at(ds + 8);
        let mut pc_offsets = Vec::with_capacity(length as usize);
        for i in 0..length {
            let p = ds + 16 + (i as usize) * 8;
            if p + 8 > d.len() {
                break;
            }
            pc_offsets.push(u32at(p));
        }
        (first_entry_with_code, pc_offsets)
    }
}

#[cfg(test)]
mod tests {
    use super::read_fingerprint;

    fn craft() -> Vec<u8> {
        let mut v = vec![0u8; 400];
        v[0..4].copy_from_slice(&[0xf5, 0xf5, 0xdc, 0xdc]);
        v[4..12].copy_from_slice(&100i64.to_le_bytes()); // length
        v[12..20].copy_from_slice(&3i64.to_le_bytes()); // kind
        v[20..52].copy_from_slice(b"0123456789abcdef0123456789abcdef");
        v[52..59].copy_from_slice(b"product");
        // v[59] 已是 \0
        v
    }

    #[test]
    fn fingerprint_reads_outer_header() {
        let v = craft();
        let fp = read_fingerprint(&v, 0).expect("应能读出指纹");
        assert_eq!(fp.kind, 3);
        assert_eq!(fp.version_hash, "0123456789abcdef0123456789abcdef");
        assert_eq!(fp.features, "product");
    }

    #[test]
    fn fingerprint_offset_shift() {
        let mut v = vec![0u8; 16];
        v.extend(craft());
        let fp = read_fingerprint(&v, 16).expect("偏移处应能读出指纹");
        assert_eq!(fp.kind, 3);
    }

    #[test]
    fn fingerprint_rejects_bad_magic_and_oob() {
        let mut v = craft();
        v[0] = 0x00;
        assert!(read_fingerprint(&v, 0).is_none());
        assert!(read_fingerprint(&v, 390).is_none());
    }
}