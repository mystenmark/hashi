// Worst case for a rotation whose Byzantine dealers are not in the new
// committee, using Hashi's reduction (build_reduced_nodes) on given weights.
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::GroupElement;
use fastcrypto_tbls::nodes::{Node, Nodes};

const MAX_BPS: u32 = 10_000;

/// Max original weight of a subset of `idx` whose reduced weight <= budget.
fn max_orig(idx: &[usize], orig: &[u32], red: &[u16], budget: u32) -> (u32, Vec<usize>) {
    let b = budget as usize;
    let mut dp: Vec<Option<(u32, Vec<usize>)>> = vec![None; b + 1];
    dp[0] = Some((0, vec![]));
    for &i in idx {
        let r = red[i] as usize;
        for c in (r..=b).rev() {
            if let Some((v, s)) = dp[c - r].clone() {
                if dp[c].as_ref().map_or(true, |(w, _)| v + orig[i] > *w) {
                    let mut s2 = s;
                    s2.push(i);
                    dp[c] = Some((v + orig[i], s2));
                }
            }
        }
    }
    dp.into_iter().flatten().max_by_key(|(v, _)| *v).unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let all: Vec<u32> = serde_json::from_str(&std::fs::read_to_string(&args[1]).unwrap()).unwrap();
    // Members removed by IgnoreMember: indices into the sorted list, from the smallest.
    let removed: usize = args.get(2).map_or(1, |s| s.parse().unwrap());
    let orig: Vec<u32> = all[..all.len() - removed].to_vec();
    let w: u32 = orig.iter().sum();
    let f = (w * 3333 / MAX_BPS).max(1);
    let t = w - 2 * f;
    let delta = (w * 800 / MAX_BPS).min(w);
    let nodes: Vec<Node<RistrettoPoint>> = orig
        .iter()
        .enumerate()
        .map(|(i, &x)| Node {
            id: i as u16,
            pk: RistrettoPoint::generator().into(),
            weight: x as u16,
        })
        .collect();
    let (rn, tr, fr) =
        Nodes::knapsack_reduce(nodes, t as u16, f as u16, delta as u16, 100).unwrap();
    let red: Vec<u16> = rn.iter().map(|n| n.weight).collect();
    let wr: u32 = red.iter().map(|&x| x as u32).sum();
    let budget = wr - tr as u32 - fr as u32;
    let completion = (w * 6667).div_ceil(MAX_BPS);
    println!(
        "new committee: n={} W={w} t={t} f={f} delta={delta}",
        orig.len()
    );
    println!(
        "reduced: W'={wr} t'={tr} f'={fr}; hurt budget per Byzantine dealer W'-t'-f'={budget}"
    );
    println!("completion threshold (original) = {completion}");
    let honest: Vec<usize> = (0..orig.len()).collect();
    let (h1, s1) = max_orig(&honest, &orig, &red, budget);
    println!(
        "one dealer: max hurt original weight = {h1} ({} members); holders = {} -> {}",
        s1.len(),
        w - h1,
        if w - h1 >= completion {
            "completes"
        } else {
            "BLOCKED"
        }
    );
    println!(
        "  slack: offline weight tolerated = {}",
        (w - h1) as i64 - completion as i64
    );
    let (h2, _) = max_orig(&honest, &orig, &red, 2 * budget);
    println!(
        "two dealers (disjoint hurt sets): max hurt = {h2}; holders = {} -> {}",
        w - h2,
        if w - h2 >= completion {
            "completes"
        } else {
            "BLOCKED"
        }
    );
    let zero = red.iter().filter(|&&x| x == 0).count();
    println!("members with reduced weight 0: {zero}");
}
