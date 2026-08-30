const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[derive(Clone)]
struct Output {
    input_cv: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        let words = compress(
            &self.input_cv,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        );
        words[..8].try_into().expect("BLAKE3 chaining value")
    }

    fn root_hash(&self) -> [u8; OUT_LEN] {
        let words = compress(
            &self.input_cv,
            &self.block_words,
            0,
            self.block_len,
            self.flags | ROOT,
        );
        words_to_bytes(&words[..8])
    }
}

pub(super) fn derive_key_bytes(context: &[u8], key_material: &[u8]) -> [u8; OUT_LEN] {
    let context_key = hash_with_mode(context, IV, DERIVE_KEY_CONTEXT);
    let context_words = bytes_to_cv(&context_key);
    hash_with_mode(key_material, context_words, DERIVE_KEY_MATERIAL)
}

fn hash_with_mode(input: &[u8], key: [u32; 8], flags: u32) -> [u8; OUT_LEN] {
    let chunk_count = input.len().div_ceil(CHUNK_LEN).max(1);
    let mut cv_stack = Vec::<[u32; 8]>::new();
    let mut final_output = None;

    for chunk_index in 0..chunk_count {
        let start = chunk_index * CHUNK_LEN;
        let end = input.len().min(start + CHUNK_LEN);
        let chunk = if start <= input.len() {
            &input[start..end]
        } else {
            &[]
        };
        let output = chunk_output(chunk, chunk_index as u64, key, flags);
        if chunk_index + 1 == chunk_count {
            final_output = Some(output);
            break;
        }
        let mut cv = output.chaining_value();
        let mut total_chunks = chunk_index + 1;
        while total_chunks & 1 == 0 {
            let left = cv_stack.pop().expect("balanced BLAKE3 CV stack");
            cv = parent_output(left, cv, key, flags).chaining_value();
            total_chunks >>= 1;
        }
        cv_stack.push(cv);
    }

    let mut output = final_output.expect("BLAKE3 always has a final chunk");
    while let Some(left) = cv_stack.pop() {
        output = parent_output(left, output.chaining_value(), key, flags);
    }
    output.root_hash()
}

fn chunk_output(chunk: &[u8], chunk_counter: u64, key: [u32; 8], flags: u32) -> Output {
    let block_count = chunk.len().div_ceil(BLOCK_LEN).max(1);
    let mut cv = key;
    for block_index in 0..block_count {
        let start = block_index * BLOCK_LEN;
        let end = chunk.len().min(start + BLOCK_LEN);
        let block = if start <= chunk.len() {
            &chunk[start..end]
        } else {
            &[]
        };
        let mut block_flags = flags;
        if block_index == 0 {
            block_flags |= CHUNK_START;
        }
        if block_index + 1 == block_count {
            block_flags |= CHUNK_END;
            return Output {
                input_cv: cv,
                block_words: bytes_to_block_words(block),
                counter: chunk_counter,
                block_len: block.len() as u32,
                flags: block_flags,
            };
        }
        let words = compress(
            &cv,
            &bytes_to_block_words(block),
            chunk_counter,
            BLOCK_LEN as u32,
            block_flags,
        );
        cv.copy_from_slice(&words[..8]);
    }
    unreachable!("BLAKE3 chunk has at least one block")
}

fn parent_output(left: [u32; 8], right: [u32; 8], key: [u32; 8], flags: u32) -> Output {
    let mut block_words = [0_u32; 16];
    block_words[..8].copy_from_slice(&left);
    block_words[8..].copy_from_slice(&right);
    Output {
        input_cv: key,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: flags | PARENT,
    }
}

fn compress(
    cv: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [0_u32; 16];
    state[..8].copy_from_slice(cv);
    state[8..12].copy_from_slice(&IV[..4]);
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = block_len;
    state[15] = flags;
    let mut message = *block_words;
    for round_index in 0..7 {
        round(&mut state, &message);
        if round_index != 6 {
            message = permute(message);
        }
    }
    for index in 0..8 {
        state[index] ^= state[index + 8];
        state[index + 8] ^= cv[index];
    }
    state
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

#[allow(clippy::too_many_arguments)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn permute(message: [u32; 16]) -> [u32; 16] {
    let mut permuted = [0_u32; 16];
    for (index, source) in MSG_PERMUTATION.iter().copied().enumerate() {
        permuted[index] = message[source];
    }
    permuted
}

fn bytes_to_block_words(bytes: &[u8]) -> [u32; 16] {
    let mut block = [0_u8; BLOCK_LEN];
    block[..bytes.len()].copy_from_slice(bytes);
    let mut words = [0_u32; 16];
    for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("four-byte BLAKE3 word"));
    }
    words
}

fn bytes_to_cv(bytes: &[u8; OUT_LEN]) -> [u32; 8] {
    let mut words = [0_u32; 8];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().expect("four-byte BLAKE3 CV word"));
    }
    words
}

fn words_to_bytes(words: &[u32]) -> [u8; OUT_LEN] {
    let mut output = [0_u8; OUT_LEN];
    for (chunk, word) in output.chunks_exact_mut(4).zip(words.iter().copied()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_context_matches_public_blake3_for_utf8_contexts() {
        for (context, material) in [
            (b"VLESS".as_slice(), b"material".as_slice()),
            (b"test context".as_slice(), b"".as_slice()),
            (b"large context".as_slice(), &[7_u8; 1500][..]),
        ] {
            assert_eq!(
                derive_key_bytes(context, material),
                blake3::derive_key(std::str::from_utf8(context).unwrap(), material)
            );
        }
    }
}
