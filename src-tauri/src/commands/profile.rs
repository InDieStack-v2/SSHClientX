use crate::{profile_runtime::ProfileLifecycle, DbState};

pub(crate) fn require_picker(state: &DbState) -> Result<(), String> {
    if state.runtime.state() == ProfileLifecycle::Picker {
        Ok(())
    } else {
        Err("[STATE] PROFILE_NOT_IN_PICKER".into())
    }
}

pub(crate) fn reject_active_delete(state: &DbState) -> Result<(), String> {
    require_picker(state).map_err(|_| "[STATE] PROFILE_ACTIVE_DELETE_REJECTED".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lock, profile_runtime, vault_store};
    use rusqlite::Connection;
    use std::sync::{Arc, Mutex};

    fn state() -> DbState {
        DbState {
            conn: Arc::new(Mutex::new(Some(Connection::open_in_memory().unwrap()))),
            dek: Mutex::new(None),
            kid: Mutex::new(None),
            generation: Mutex::new(None),
            sender_id: Mutex::new(None),
            db_path: Mutex::new(None),
            active_profile: Mutex::new(None),
            hlc: Mutex::new(None),
            writer_claim: Mutex::new(None),
            lock_state: Mutex::new(lock::LockState::Unlocked),
            platform_auth_failures: Mutex::new(0),
            runtime: profile_runtime::ProfileRuntime::new(),
            save_coordinator: vault_store::VaultSaveCoordinator::new(),
        }
    }

    #[test]
    fn picker_gate_rejects_active_runtime() {
        let state = state();
        state.runtime.select().unwrap();
        assert_eq!(
            require_picker(&state).unwrap_err(),
            "[STATE] PROFILE_NOT_IN_PICKER"
        );
        assert_eq!(
            reject_active_delete(&state).unwrap_err(),
            "[STATE] PROFILE_ACTIVE_DELETE_REJECTED"
        );
    }
}
