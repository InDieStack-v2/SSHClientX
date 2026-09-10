use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, Weak,
};
use std::time::Duration;
use tokio::sync::Notify;

pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileLifecycle {
    Picker,
    Selected,
    Unlocked,
    Locked,
    Closing,
}

#[derive(Debug)]
struct ResourceState {
    name: String,
    done: AtomicBool,
    notify: Notify,
}

#[derive(Debug)]
struct RuntimeInner {
    state: ProfileLifecycle,
    epoch: u64,
    next_resource_id: u64,
    resources: HashMap<u64, Arc<ResourceState>>,
}

#[derive(Clone, Debug)]
pub struct ProfileRuntime {
    inner: Arc<Mutex<RuntimeInner>>,
}

#[derive(Debug)]
pub struct ResourceRegistration {
    runtime: Weak<Mutex<RuntimeInner>>,
    id: u64,
    state: Arc<ResourceState>,
    epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeAdmission {
    pub epoch: u64,
}

impl Default for ProfileRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileRuntime {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RuntimeInner {
                state: ProfileLifecycle::Picker,
                epoch: 0,
                next_resource_id: 1,
                resources: HashMap::new(),
            })),
        }
    }

    pub fn state(&self) -> ProfileLifecycle {
        self.inner
            .lock()
            .expect("profile runtime mutex poisoned")
            .state
    }

    pub fn epoch(&self) -> u64 {
        self.inner
            .lock()
            .expect("profile runtime mutex poisoned")
            .epoch
    }

    pub fn select(&self) -> Result<(), String> {
        self.transition(ProfileLifecycle::Picker, ProfileLifecycle::Selected)
    }

    pub fn unlock(&self) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "[STATE] PROFILE_RUNTIME_POISONED")?;
        match inner.state {
            ProfileLifecycle::Selected | ProfileLifecycle::Locked => {
                inner.state = ProfileLifecycle::Unlocked;
                Ok(())
            }
            other => Err(format!(
                "[STATE] INVALID_PROFILE_TRANSITION: {:?} -> Unlocked",
                other
            )),
        }
    }

    pub fn lock(&self) -> Result<(), String> {
        self.transition(ProfileLifecycle::Unlocked, ProfileLifecycle::Locked)
    }

    pub fn begin_close(&self) -> Result<RuntimeAdmission, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "[STATE] PROFILE_RUNTIME_POISONED")?;
        match inner.state {
            ProfileLifecycle::Selected | ProfileLifecycle::Unlocked | ProfileLifecycle::Locked => {
                inner.state = ProfileLifecycle::Closing;
                inner.epoch = inner.epoch.wrapping_add(1);
                Ok(RuntimeAdmission { epoch: inner.epoch })
            }
            ProfileLifecycle::Closing => Ok(RuntimeAdmission { epoch: inner.epoch }),
            ProfileLifecycle::Picker => Err("[STATE] PROFILE_NOT_ACTIVE".into()),
        }
    }

    pub fn finish_close(
        &self,
        admission: RuntimeAdmission,
        result: Result<(), String>,
    ) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "[STATE] PROFILE_RUNTIME_POISONED")?;
        if inner.state != ProfileLifecycle::Closing || inner.epoch != admission.epoch {
            return Err("[STATE] PROFILE_CLOSE_STALE_EPOCH".into());
        }
        match result {
            Ok(()) => {
                if inner
                    .resources
                    .values()
                    .any(|resource| !resource.done.load(Ordering::Acquire))
                {
                    return Err("[STATE] PROFILE_RESOURCES_PENDING".into());
                }
                inner.resources.clear();
                inner.state = ProfileLifecycle::Picker;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    pub fn admit(&self) -> Result<RuntimeAdmission, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| "[STATE] PROFILE_RUNTIME_POISONED")?;
        match inner.state {
            ProfileLifecycle::Unlocked | ProfileLifecycle::Locked => {
                Ok(RuntimeAdmission { epoch: inner.epoch })
            }
            ProfileLifecycle::Closing => Err("[STATE] PROFILE_CLOSING".into()),
            ProfileLifecycle::Picker | ProfileLifecycle::Selected => {
                Err("[STATE] PROFILE_NOT_UNLOCKED".into())
            }
        }
    }

    pub fn admission_is_current(&self, admission: RuntimeAdmission) -> bool {
        self.inner
            .lock()
            .map(|inner| {
                inner.epoch == admission.epoch
                    && matches!(
                        inner.state,
                        ProfileLifecycle::Unlocked | ProfileLifecycle::Locked
                    )
            })
            .unwrap_or(false)
    }

    pub fn register(&self, name: impl Into<String>) -> Result<ResourceRegistration, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "[STATE] PROFILE_RUNTIME_POISONED")?;
        if !matches!(
            inner.state,
            ProfileLifecycle::Unlocked | ProfileLifecycle::Locked
        ) {
            return Err("[STATE] PROFILE_RESOURCE_ADMISSION_REJECTED".into());
        }
        let id = inner.next_resource_id;
        inner.next_resource_id = inner.next_resource_id.wrapping_add(1);
        let state = Arc::new(ResourceState {
            name: name.into(),
            done: AtomicBool::new(false),
            notify: Notify::new(),
        });
        inner.resources.insert(id, Arc::clone(&state));
        Ok(ResourceRegistration {
            runtime: Arc::downgrade(&self.inner),
            id,
            state,
            epoch: inner.epoch,
        })
    }

    pub async fn shutdown(&self, timeout: Duration) -> Result<(), String> {
        let resources: Vec<Arc<ResourceState>> = {
            let inner = self
                .inner
                .lock()
                .map_err(|_| "[STATE] PROFILE_RUNTIME_POISONED")?;
            inner.resources.values().cloned().collect()
        };
        for resource in resources {
            if resource.done.load(Ordering::Acquire) {
                continue;
            }
            tokio::time::timeout(timeout, async {
                while !resource.done.load(Ordering::Acquire) {
                    resource.notify.notified().await;
                }
            })
            .await
            .map_err(|_| format!("[STATE] PROFILE_SHUTDOWN_TIMEOUT: {}", resource.name))?;
        }
        Ok(())
    }

    pub async fn wait_for_resources(&self, timeout: Duration) -> Result<(), String> {
        self.shutdown(timeout).await
    }

    fn transition(&self, from: ProfileLifecycle, to: ProfileLifecycle) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "[STATE] PROFILE_RUNTIME_POISONED")?;
        if inner.state != from {
            return Err(format!(
                "[STATE] INVALID_PROFILE_TRANSITION: {:?} -> {:?}",
                inner.state, to
            ));
        }
        inner.state = to;
        Ok(())
    }
}

impl ResourceRegistration {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn acknowledge(&self) {
        if !self.state.done.swap(true, Ordering::AcqRel) {
            self.state.notify.notify_waiters();
        }
    }
}

impl Drop for ResourceRegistration {
    fn drop(&mut self) {
        self.acknowledge();
        if let Some(runtime) = self.runtime.upgrade() {
            if let Ok(mut inner) = runtime.lock() {
                if inner.state == ProfileLifecycle::Picker {
                    inner.resources.remove(&self.id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lifecycle_rejects_admission_after_close_begins() {
        let runtime = ProfileRuntime::new();
        runtime.select().unwrap();
        runtime.unlock().unwrap();
        let admission = runtime.admit().unwrap();
        let closing = runtime.begin_close().unwrap();
        assert!(closing.epoch > admission.epoch);
        assert_eq!(runtime.admit().unwrap_err(), "[STATE] PROFILE_CLOSING");
        runtime
            .wait_for_resources(Duration::from_millis(10))
            .await
            .unwrap();
        runtime.finish_close(closing, Ok(())).unwrap();
        assert_eq!(runtime.state(), ProfileLifecycle::Picker);
    }

    #[tokio::test]
    async fn close_waits_for_resource_acknowledgement() {
        let runtime = ProfileRuntime::new();
        runtime.select().unwrap();
        runtime.unlock().unwrap();
        let resource = runtime.register("terminal").unwrap();
        let close = runtime.begin_close().unwrap();
        let wait = runtime.wait_for_resources(Duration::from_millis(100));
        resource.acknowledge();
        wait.await.unwrap();
        runtime.finish_close(close, Ok(())).unwrap();
    }

    #[tokio::test]
    async fn timeout_keeps_runtime_unavailable() {
        let runtime = ProfileRuntime::new();
        runtime.select().unwrap();
        runtime.unlock().unwrap();
        let _resource = runtime.register("sftp-transfer").unwrap();
        let close = runtime.begin_close().unwrap();
        let err = runtime
            .wait_for_resources(Duration::from_millis(1))
            .await
            .unwrap_err();
        assert!(err.starts_with("[STATE] PROFILE_SHUTDOWN_TIMEOUT"));
        assert_eq!(runtime.state(), ProfileLifecycle::Closing);
        assert!(runtime.finish_close(close, Err(err)).is_err());
    }

    #[tokio::test]
    async fn reopening_profile_rejects_the_previous_epoch() {
        let runtime = ProfileRuntime::new();
        runtime.select().unwrap();
        runtime.unlock().unwrap();
        let old = runtime.admit().unwrap();
        let close = runtime.begin_close().unwrap();
        runtime
            .wait_for_resources(Duration::from_millis(10))
            .await
            .unwrap();
        runtime.finish_close(close, Ok(())).unwrap();
        runtime.select().unwrap();
        runtime.unlock().unwrap();
        let current = runtime.admit().unwrap();
        assert!(current.epoch > old.epoch);
        assert!(!runtime.admission_is_current(old));
        assert!(runtime.admission_is_current(current));
    }
}
