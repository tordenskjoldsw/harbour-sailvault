use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroizing;

pub(crate) enum Argon2Failure {
    OutOfMemory,
    InvalidParameters,
}

/// Runs Argon2 with working memory owned by the caller. The crate's own
/// `hash_password_into` allocates infallibly, aborting the process on
/// failure, and frees the memory unwiped although its last block holds the
/// derived key. Here the memory is reserved fallibly and zeroized on drop.
pub(crate) fn hash_into(
    algorithm: Algorithm,
    version: Version,
    params: Params,
    password: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> Result<(), Argon2Failure> {
    let block_count = params.block_count();
    let mut blocks: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    blocks
        .try_reserve_exact(block_count)
        .map_err(|_| Argon2Failure::OutOfMemory)?;
    blocks.resize(block_count, Block::default());
    Argon2::new(algorithm, version, params)
        .hash_password_into_with_memory(password, salt, out, blocks.as_mut_slice())
        .map_err(|_| Argon2Failure::InvalidParameters)
}
