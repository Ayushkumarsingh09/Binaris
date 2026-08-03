/// Shannon entropy in bits/byte (0.0–8.0).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

pub fn is_high_entropy(entropy: f64) -> bool {
    entropy >= 7.2
}

pub fn is_likely_packed_or_encrypted(entropy: f64, size: usize) -> bool {
    size >= 256 && entropy >= 7.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_entropy_for_constant() {
        let data = vec![0u8; 1024];
        assert!(shannon_entropy(&data) < 0.01);
    }

    #[test]
    fn high_entropy_for_randomish() {
        let data: Vec<u8> = (0..255).cycle().take(4096).collect();
        assert!(shannon_entropy(&data) > 7.5);
    }
}
