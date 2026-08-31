//! SDK Profile 自动识别。
//!
//! 两级策略：
//! 1. 版本指纹精确命中：快照外层 32B 版本 hash（每版 VM 构建唯一）查
//!    `profiles/sdk/version_hashes.json` → 直接锁定 profile（官方 SDK 构建的产物）。
//! 2. 结构探针：hash 未命中（Flutter 引擎自编译、自定义 fork 等）时，对全部嵌入
//!    profile 做 alloc 段试解析（vm+iso），筛出「不漂移」候选，再以 fill 产出的
//!    函数/类/库计数决胜（错误 profile 解析出的名字明显更少/更碎）。

use crate::engine::fill::fill_snapshot;
use crate::engine::snapshot::{read_fingerprint, Snapshot};
use crate::profile::{abi_for_hash, sdk_registry, SdkProfile};

pub struct Detection {
    /// 是否由版本 hash 精确命中
    pub hash_hit: bool,
    /// 初筛阶段是否零告警（alloc 不漂移）
    pub clean: bool,
}

#[derive(Clone, Copy)]
struct Probe {
    clean: bool,
}

/// alloc 段试解析：vm/iso 都能解析且计数自洽则成功；
/// clean = 无 alloc mismatch / drift 类告警。
fn probe(p: &SdkProfile, data: &[u8], vm_off: usize, iso_off: usize) -> Option<Probe> {
    let mut warns = Vec::new();
    let vm = if p.format.single_snapshot {
        Snapshot::stub(p, data)
    } else {
        Snapshot::parse(p, data, vm_off, Some(&mut warns)).ok()?
    };
    let iso = Snapshot::parse(p, data, iso_off, Some(&mut warns)).ok()?;
    let sane = (p.format.single_snapshot || vm.hdr.get("num_objects") > 0)
        && iso.hdr.get("num_objects") > 0
        && iso.hdr.get("num_clusters") > 0
        && !iso.clusters.is_empty();
    if !sane {
        return None;
    }
    Some(Probe { clean: warns.is_empty() })
}

/// fill 决胜分：解析出的函数/类/库数（错误 profile 显著更低，或 fill 直接失败）。
fn fill_score(p: &SdkProfile, data: &[u8], vm_off: usize, iso_off: usize) -> Option<usize> {
    let mut warns = Vec::new();
    let mut vm = if p.format.single_snapshot {
        Snapshot::stub(p, data)
    } else {
        Snapshot::parse(p, data, vm_off, Some(&mut warns)).ok()?
    };
    let mut iso = Snapshot::parse(p, data, iso_off, Some(&mut warns)).ok()?;
    fill_snapshot(p, &mut vm, Some(&mut warns)).ok()?;
    fill_snapshot(p, &mut iso, Some(&mut warns)).ok()?;
    Some(iso.functions.len() * 4 + iso.classes.len() + iso.libraries.len() + vm.classes.len())
}

/// 自动识别 SDK Profile。None = 无法识别（调用方回退默认并告警）。
pub fn detect_sdk(
    data: &[u8],
    vm_off: usize,
    iso_off: usize,
) -> Option<(&'static SdkProfile, Detection)> {
    let registry = sdk_registry();

    // 1) 版本 hash 精确命中
    if let Some(fp) = read_fingerprint(data, vm_off) {
        if let Some(abi) = abi_for_hash(&fp.version_hash) {
            if let Some((_, p)) = registry.iter().find(|(a, _)| *a == abi) {
                if probe(p, data, vm_off, iso_off).is_some() {
                    return Some((p, Detection { hash_hit: true, clean: true }));
                }
                // hash 命中但解析不自洽（罕见）→ 落入结构探针
            }
        }
    }

    // 2) 结构探针：alloc 段试解析 + fill 决胜
    let single = vm_off == iso_off;
    let mut cands: Vec<(&'static SdkProfile, Probe)> = Vec::new();
    for (_, p) in registry
        .iter()
        .filter(|(_, p)| p.status != "unsupported" && p.format.single_snapshot == single)
    {
        if let Some(pr) = probe(p, data, vm_off, iso_off) {
            cands.push((p, pr));
        }
    }
    if cands.is_empty() {
        return None;
    }
    // 全净候选优先；否则退而求其次（带告警但可解析）
    let clean: Vec<(&'static SdkProfile, Probe)> =
        cands.iter().filter(|(_, pr)| pr.clean).copied().collect();
    let pool: &[(&'static SdkProfile, Probe)] = if !clean.is_empty() { &clean } else { &cands };

    let pick: (&'static SdkProfile, Probe) = if pool.len() == 1 {
        pool[0]
    } else {
        let mut best: Option<(&'static SdkProfile, usize, bool)> = None;
        for (p, pr) in pool.iter().take(6) {
            let (p, pr) = (*p, *pr);
            let (score, is_clean) = fill_score(p, data, vm_off, iso_off)
                .map(|sc| (sc, pr.clean))
                .unwrap_or((0, pr.clean));
            if best.map(|(_, bs, _)| score > bs).unwrap_or(true) {
                best = Some((p, score, is_clean));
            }
        }
        let (p, _, is_clean) = best?;
        (p, Probe { clean: is_clean })
    };
    Some((
        pick.0,
        Detection { hash_hit: false, clean: pick.1.clean },
    ))
}

/// main 入口的默认选择：识别成功打印所选版本与判定方式；
/// 识别失败回退内嵌 dart-3.3.4 并显式告警。
pub fn detect_or_default(
    data: &[u8],
    offs: (u64, u64, u64),
    s: &crate::locale::Messages,
) -> &'static SdkProfile {
    match detect_sdk(data, offs.0 as usize, offs.1 as usize) {
        Some((p, det)) => {
            let basis = if det.hash_hit {
                s.detect_basis_hash
            } else if det.clean {
                s.detect_basis_probe
            } else {
                s.detect_basis_low
            };
            println!("{}: {}（{basis}）", s.sdk_profile_label, p.abi);
            p
        }
        None => {
            eprintln!("{}", s.detect_fallback);
            sdk_registry()
                .iter()
                .find(|(abi, _)| abi == "dart/3.3.4")
                .map(|(_, p)| p)
                .expect("内嵌 dart-3.3.4 profile 缺失")
        }
    }
}