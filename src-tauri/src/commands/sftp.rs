#[allow(dead_code)]
pub(crate) fn overwrite_conflict(path: &str) -> String {
    format!("EXISTS:{path}")
}

#[allow(dead_code)]
pub(crate) fn is_secondary_session(session_id: &str) -> bool {
    session_id.ends_with("::sftp") || session_id.ends_with("::fwd")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_sftp_conflict_and_secondary_session_contracts() {
        assert_eq!(overwrite_conflict("/tmp/a.txt"), "EXISTS:/tmp/a.txt");
        assert!(is_secondary_session("server::sftp"));
        assert!(is_secondary_session("server::fwd"));
        assert!(!is_secondary_session("server"));
    }
}
