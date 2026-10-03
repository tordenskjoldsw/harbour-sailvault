//! Random bytes from the kernel through `getrandom(2)`. This is the core's
//! only system call besides memory allocation.

pub(crate) fn fill(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::getrandom(buffer)
}

pub(crate) fn array<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut bytes = [0u8; N];
    fill(&mut bytes)?;
    Ok(bytes)
}
