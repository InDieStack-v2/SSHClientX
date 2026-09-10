use std::sync::{Arc, Condvar, Mutex};

#[derive(Debug)]
struct CoordinatorState {
    busy: bool,
    next_admission: u64,
}

#[derive(Clone, Debug)]
pub struct VaultSaveCoordinator {
    state: Arc<(Mutex<CoordinatorState>, Condvar)>,
}

#[derive(Debug)]
pub struct SavePermit {
    coordinator: VaultSaveCoordinator,
    admission_sequence: u64,
}

impl Default for VaultSaveCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultSaveCoordinator {
    pub fn new() -> Self {
        Self {
            state: Arc::new((
                Mutex::new(CoordinatorState {
                    busy: false,
                    next_admission: 0,
                }),
                Condvar::new(),
            )),
        }
    }

    /// Admit one mutation/save operation in a monotonic order. The permit
    /// owns the serialized boundary and is held through durable replacement.
    pub fn acquire(&self) -> Result<SavePermit, String> {
        let (lock, wake) = &*self.state;
        let mut state = lock
            .lock()
            .map_err(|_| "[STATE] SAVE_COORDINATOR_POISONED".to_string())?;
        while state.busy {
            state = wake
                .wait(state)
                .map_err(|_| "[STATE] SAVE_COORDINATOR_POISONED".to_string())?;
        }
        state.busy = true;
        state.next_admission = state.next_admission.wrapping_add(1);
        Ok(SavePermit {
            coordinator: self.clone(),
            admission_sequence: state.next_admission,
        })
    }

    #[cfg(test)]
    fn admission_count(&self) -> u64 {
        self.state
            .0
            .lock()
            .expect("save coordinator mutex poisoned")
            .next_admission
    }

    pub async fn acquire_async(&self) -> Result<SavePermit, String> {
        let coordinator = self.clone();
        tokio::task::spawn_blocking(move || coordinator.acquire())
            .await
            .map_err(|error| format!("[STATE] SAVE_COORDINATOR_JOIN: {error}"))?
    }
}

impl SavePermit {
    pub fn admission_sequence(&self) -> u64 {
        self.admission_sequence
    }

    pub fn next_generation(&self, current: u64) -> u64 {
        current.saturating_add(1)
    }
}

impl Drop for SavePermit {
    fn drop(&mut self) {
        let (lock, wake) = &*self.coordinator.state;
        if let Ok(mut state) = lock.lock() {
            state.busy = false;
            wake.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn admissions_are_monotonic_and_serialized() {
        let coordinator = Arc::new(VaultSaveCoordinator::new());
        let first = coordinator.acquire().unwrap();
        assert_eq!(first.admission_sequence(), 1);

        let other = Arc::clone(&coordinator);
        let join = thread::spawn(move || {
            let permit = other.acquire().unwrap();
            permit.admission_sequence()
        });
        thread::sleep(Duration::from_millis(5));
        assert_eq!(coordinator.admission_count(), 1);
        drop(first);
        assert_eq!(join.join().unwrap(), 2);
    }

    #[test]
    fn failed_permit_release_allows_the_next_save() {
        let coordinator = VaultSaveCoordinator::new();
        let first = coordinator.acquire().unwrap();
        assert_eq!(first.next_generation(7), 8);
        drop(first);
        let second = coordinator.acquire().unwrap();
        assert_eq!(second.admission_sequence(), 2);
    }
}
