use crate::ssh_manager::SshState;

#[allow(dead_code)]
pub(crate) async fn session_is_current(
    state: &SshState,
    session_id: &str,
    generation: u64,
) -> bool {
    state
        .session_generation
        .lock()
        .await
        .get(session_id)
        .copied()
        == Some(generation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_manager::SshState;

    #[tokio::test]
    async fn stale_session_generation_is_rejected() {
        let state = SshState::new();
        state.session_generation.lock().await.insert("s".into(), 2);
        assert!(session_is_current(&state, "s", 2).await);
        assert!(!session_is_current(&state, "s", 1).await);
    }
}
