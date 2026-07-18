use std::io;

use nix::unistd::{Uid, User};

/// Host account information used to create the corresponding guest account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUser {
    /// Login name used for the guest account, home directory, and SSH login.
    pub name: String,
    /// Numeric ID preserved so shared files have the same owner on host and guest.
    pub uid: u32,
    /// Display name passed to the guest account's GECOS/comment field.
    pub gecos: String,
}

/// Resolves the effective process user through the host's passwd database.
///
/// `User::from_uid` wraps `getpwuid_r`, so it uses configured NSS providers on
/// Linux and Directory Services on macOS rather than untrusted environment
/// variables such as `USER`. The account name identifies the guest login, and
/// retaining its UID keeps ownership consistent for host files mounted into
/// the guest.
///
/// A traditional passwd record representing the returned account could look
/// like this:
///
/// ```text
/// johndoe:x:1000:1000:John Doe,Room 42,555-0100,555-0101:/home/johndoe:/bin/bash
/// ```
///
/// Its colon-separated fields are the login name (`johndoe`), password
/// placeholder (`x`), UID (`1000`), primary GID (`1000`), GECOS metadata, home
/// directory, and login shell. This function does not parse that text directly;
/// `User::from_uid` asks the host account database for the effective UID and
/// returns those fields in a structured form. From the example it retains the
/// name `johndoe`, UID `1000`, and display name `John Doe`. The password, GID,
/// host home directory, host shell, and remaining GECOS components are not
/// copied into `HostUser`.
///
/// GECOS is the passwd entry's human-readable account metadata. Its first
/// comma-separated component conventionally contains the user's full display
/// name, which is passed to the guest's account comment field. GECOS follows
/// the host locale and may not be UTF-8, so it is converted lossily. Empty
/// display names fall back to the account name.
pub fn current_host_user() -> io::Result<HostUser> {
    let uid = Uid::effective();
    let user = User::from_uid(uid)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("unable to resolve effective host user {uid}"),
        )
    })?;

    if user.name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty account name in passwd entry",
        ));
    }

    let gecos = user.gecos.to_string_lossy();
    let gecos = gecos
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&user.name)
        .to_owned();

    Ok(HostUser {
        name: user.name,
        uid: user.uid.as_raw(),
        gecos,
    })
}
