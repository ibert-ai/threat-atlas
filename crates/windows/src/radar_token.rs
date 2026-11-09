//! The user's own Cloudflare Radar token on Windows: stored as a generic credential in Windows
//! Credential Manager (per user, this machine, protected by the user's Windows logon), entered
//! through the standard Windows credential dialog. Never written to settings, logs or the title.
use windows_sys::Win32::{
    Foundation::HWND,
    Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredUIPromptForCredentialsW, CredWriteW, CREDENTIALW,
        CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST, CREDUI_FLAGS_GENERIC_CREDENTIALS,
        CREDUI_FLAGS_KEEP_USERNAME, CREDUI_INFOW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    },
};

/// Credential Manager entry name, shown under Windows Credentials > Generic Credentials.
pub const TARGET: &str = "AtlasSOC/CloudflareRadarRead";
const USER: &str = "Cloudflare API token";
/// Generous buffer; Cloudflare tokens are about 40-60 characters.
const MAX_CHARS: usize = 1024;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

/// Same acceptance rule as the macOS beta: non-empty, bounded, a single line.
pub fn valid(token: &str) -> bool {
    let token = token.trim();
    !token.is_empty() && token.len() < 4096 && !token.chars().any(|c| c.is_control())
}

pub fn read() -> Option<String> {
    let target = wide(TARGET);
    let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
    unsafe {
        if CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) == 0
            || credential.is_null()
        {
            return None;
        }
        let blob = std::slice::from_raw_parts(
            (*credential).CredentialBlob,
            (*credential).CredentialBlobSize as usize,
        );
        let token = String::from_utf8(blob.to_vec()).ok();
        CredFree(credential as *const _);
        token.filter(|t| valid(t))
    }
}

pub fn exists() -> bool {
    read().is_some()
}

pub fn save(token: &str) -> bool {
    let token = token.trim();
    if !valid(token) {
        return false;
    }
    let mut target = wide(TARGET);
    let mut user = wide(USER);
    let mut blob = token.as_bytes().to_vec();
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: user.as_mut_ptr(),
        ..Default::default()
    };
    let saved = unsafe { CredWriteW(&credential, 0) != 0 };
    blob.iter_mut().for_each(|b| *b = 0);
    saved
}

pub fn remove() -> bool {
    let target = wide(TARGET);
    unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) != 0 }
}

/// Standard Windows credential dialog: the user pastes the token into the password field.
/// Returns None when cancelled or empty. The dialog itself never stores anything.
pub fn prompt(owner: HWND) -> Option<String> {
    let message = wide(
        "Paste your own Cloudflare API token (permission Account > Radar > Read) into the password field.\n\nIt is stored only in Windows Credential Manager for your account on this PC and sent only to api.cloudflare.com.",
    );
    let caption = wide("AtlasSOC - Cloudflare Radar token");
    let info = CREDUI_INFOW {
        cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
        hwndParent: owner,
        pszMessageText: message.as_ptr(),
        pszCaptionText: caption.as_ptr(),
        hbmBanner: std::ptr::null_mut(),
    };
    let target = wide(TARGET);
    let mut user = vec![0u16; 514];
    for (slot, unit) in user.iter_mut().zip(USER.encode_utf16()) {
        *slot = unit;
    }
    let mut password = vec![0u16; MAX_CHARS];
    let mut save = 0;
    let result = unsafe {
        CredUIPromptForCredentialsW(
            &info,
            target.as_ptr(),
            std::ptr::null(),
            0,
            user.as_mut_ptr(),
            user.len() as u32,
            password.as_mut_ptr(),
            password.len() as u32,
            &mut save,
            CREDUI_FLAGS_GENERIC_CREDENTIALS
                | CREDUI_FLAGS_ALWAYS_SHOW_UI
                | CREDUI_FLAGS_DO_NOT_PERSIST
                | CREDUI_FLAGS_KEEP_USERNAME,
        )
    };
    let end = password
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(password.len());
    let token = (result == 0).then(|| String::from_utf16_lossy(&password[..end]));
    password.iter_mut().for_each(|c| *c = 0);
    token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::valid;
    #[test]
    fn token_validation_matches_macos() {
        assert!(valid(" abc_DEF-123 "));
        assert!(!valid(""));
        assert!(!valid("   "));
        assert!(!valid("two\nlines"));
        assert!(!valid(&"x".repeat(5000)));
    }
}
