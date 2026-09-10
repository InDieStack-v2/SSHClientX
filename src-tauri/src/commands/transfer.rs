#[allow(dead_code)]
pub(crate) fn secondary_session_id(session_id: &str, suffix: &str) -> String {
    format!("{session_id}::{suffix}")
}

#[allow(dead_code)]
pub(crate) fn transfer_event_name(session_id: &str) -> String {
    format!("sftp-transfer-{session_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_secondary_session_and_transfer_event_names() {
        assert_eq!(secondary_session_id("server", "sftp"), "server::sftp");
        assert_eq!(
            transfer_event_name("server::sftp"),
            "sftp-transfer-server::sftp"
        );
    }
}
