use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePolicy {
    pub root: PathBuf,
    pub max_depth: usize,
    pub allow_write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeMount {
    pub id: String,
    pub mount_path: PathBuf,
    pub read_only: bool,
}

impl WorkspacePolicy {
    pub fn new(root: impl Into<PathBuf>, max_depth: usize, allow_write: bool) -> Self {
        Self {
            root: root.into(),
            max_depth,
            allow_write,
        }
    }

    pub fn validate_path(&self, requested: &Path) -> Result<PathBuf, String> {
        if requested.is_absolute() {
            return Err("workspace paths must be relative to the sandbox root".into());
        }

        let mut components = Vec::new();
        for component in requested.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    if components.is_empty() {
                        return Err("directory traversal is not allowed".into());
                    }
                    components.pop();
                }
                Component::Normal(part) => {
                    components.push(PathBuf::from(part));
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err("unsupported path form in workspace".into());
                }
            }
        }

        if components.len() > self.max_depth {
            return Err("workspace path exceeds max depth".into());
        }

        Ok(self.root.join(PathBuf::from_iter(components)))
    }
}

impl VolumeMount {
    pub fn new(id: impl Into<String>, mount_path: impl Into<PathBuf>, read_only: bool) -> Self {
        Self {
            id: id.into(),
            mount_path: mount_path.into(),
            read_only,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{VolumeMount, WorkspacePolicy};
    use std::path::Path;

    #[test]
    fn workspace_rejects_directory_traversal() {
        let policy = WorkspacePolicy::new("/tmp/workspace", 4, true);
        assert!(policy.validate_path(Path::new("../secrets")).is_err());
    }

    #[test]
    fn workspace_allows_safe_relative_paths() {
        let policy = WorkspacePolicy::new("/tmp/workspace", 4, true);
        let resolved = policy.validate_path(Path::new("project/data/output.txt")).unwrap();
        assert_eq!(resolved, Path::new("/tmp/workspace/project/data/output.txt"));
    }

    #[test]
    fn volume_mount_is_explicitly_typed() {
        let mount = VolumeMount::new("cache-vol", "/var/cache/workloads", true);
        assert!(mount.read_only);
    }
}
