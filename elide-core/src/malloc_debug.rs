//! Debug hook exposing glibc's `malloc_info(3)` from a live process.
//!
//! `malloc_info` reports per-arena allocator state (arena count, free
//! bytes per arena, total mmapped bytes) — the ground truth behind an
//! RSS number. It can only be called from inside the process, so this
//! installs a dedicated thread that waits for `SIGUSR1` and writes the
//! XML dump to `/tmp/malloc_info.<pid>.xml` on each delivery.
//!
//! `sigwait` on a dedicated thread keeps `malloc_info` (which is not
//! async-signal-safe) out of signal-handler context. The signal is
//! blocked process-wide, so install this before spawning other threads
//! — they inherit the mask, and `SIGUSR1` is only ever consumed here.
//!
//! Best-effort by design: failures are swallowed. Non-glibc targets get
//! a no-op.

#[cfg(all(unix, target_env = "gnu"))]
pub fn install_sigusr1_dump() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        let _ = std::thread::Builder::new()
            .name("malloc-info".into())
            .spawn(move || {
                let mut sig: libc::c_int = 0;
                loop {
                    if libc::sigwait(&set, &mut sig) != 0 {
                        return;
                    }
                    dump();
                }
            });
    }
}

#[cfg(all(unix, target_env = "gnu"))]
fn dump() {
    let path = format!("/tmp/malloc_info.{}.xml\0", std::process::id());
    unsafe {
        let f = libc::fopen(path.as_ptr().cast(), c"w".as_ptr());
        if !f.is_null() {
            libc::malloc_info(0, f);
            libc::fclose(f);
        }
    }
}

#[cfg(not(all(unix, target_env = "gnu")))]
pub fn install_sigusr1_dump() {}
