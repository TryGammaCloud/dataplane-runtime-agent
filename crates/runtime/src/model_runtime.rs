#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelRuntimeState {
    Stopped,
    Starting,
    Running,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelManifest {
    pub model_name: String,
    pub model_version: String,
    pub image_digest: String,
    pub requires_attestation: bool,
    pub resource_limit_mib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceRuntime {
    pub manifest: Option<ModelManifest>,
    pub state: ModelRuntimeState,
}

impl InferenceRuntime {
    pub fn new() -> Self {
        Self {
            manifest: None,
            state: ModelRuntimeState::Stopped,
        }
    }

    pub fn install_manifest(
        &mut self,
        model_name: impl Into<String>,
        model_version: impl Into<String>,
        image_digest: impl Into<String>,
        requires_attestation: bool,
        resource_limit_mib: u64,
    ) -> Result<(), String> {
        let model_name = model_name.into();
        if model_name.trim().is_empty() {
            return Err("model_name is required".into());
        }
        if resource_limit_mib == 0 {
            return Err("resource_limit_mib must be > 0".into());
        }
        self.manifest = Some(ModelManifest {
            model_name,
            model_version: model_version.into(),
            image_digest: image_digest.into(),
            requires_attestation,
            resource_limit_mib,
        });
        self.state = ModelRuntimeState::Starting;
        Ok(())
    }

    pub fn health_check(&self) -> Result<(), String> {
        match self.state {
            ModelRuntimeState::Running => Ok(()),
            ModelRuntimeState::Stopped => Err("inference runtime is stopped".into()),
            ModelRuntimeState::Starting => Err("inference runtime is still starting".into()),
            ModelRuntimeState::Failed => Err("inference runtime failed".into()),
        }
    }

    pub fn mark_running(&mut self) {
        self.state = ModelRuntimeState::Running;
    }

    pub fn mark_failed(&mut self) {
        self.state = ModelRuntimeState::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::{InferenceRuntime, ModelRuntimeState};

    #[test]
    fn manifest_requires_nonempty_name_and_resources() {
        let mut runtime = InferenceRuntime::new();
        assert!(runtime
            .install_manifest("demo", "v1", "sha256:abc", true, 0)
            .is_err());
    }

    #[test]
    fn health_check_requires_running_state() {
        let mut runtime = InferenceRuntime::new();
        runtime
            .install_manifest("demo", "v1", "sha256:abc", true, 2048)
            .unwrap();
        assert!(runtime.health_check().is_err());
        runtime.mark_running();
        assert!(runtime.health_check().is_ok());
        assert_eq!(runtime.state, ModelRuntimeState::Running);
    }
}
