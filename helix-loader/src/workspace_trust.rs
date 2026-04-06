use std::{collections::HashMap, fs, path::PathBuf};

use crate::{data_dir, workspace_exclude_file, workspace_trust_file};

pub struct WorkspaceTrust(HashMap<PathBuf, TrustUntrustStatus>);

#[derive(Clone, Copy)]
pub enum TrustStatus {
    Untrusted,
    Trusted,
}

impl WorkspaceTrust {
    /// Loads `WorkspaceTrust`.
    pub fn load() -> Self {
        let mut workspaces = HashMap::new();

        match fs::read_to_string(workspace_exclude_file()) {
            Ok(exclude_file) => {
                for line in exclude_file.split('\n') {
                    if !line.is_empty() {
                        let path = PathBuf::from(line);
                        workspaces.insert(path, TrustUntrustStatus::DenyAlways);
                    }
                }
            }
            Err(e) => log::error!("workspace file couldn't be read: {:?}", e),
        };

        match fs::read_to_string(workspace_trust_file()) {
            Ok(trust_file) => {
                for line in trust_file.split('\n') {
                    if !line.is_empty() {
                        let path = PathBuf::from(line);
                        workspaces.insert(path, TrustUntrustStatus::AllowAlways);
                    }
                }
            }
            Err(e) => log::error!("workspace file couldn't be read: {:?}", e),
        };

        WorkspaceTrust(workspaces)
    }

    pub fn load_empty() -> Self {
        WorkspaceTrust(HashMap::new())
    }

    pub fn query_workspace(&self, insecure: bool) -> TrustStatus {
        match self.query_workspace_with_explicit_untrust(insecure) {
            Some(TrustUntrustStatus::AllowAlways) => TrustStatus::Trusted,
            _ => TrustStatus::Untrusted,
        }
    }

    pub fn query_workspace_with_explicit_untrust(
        &self,
        insecure: bool,
    ) -> Option<TrustUntrustStatus> {
        if insecure {
            return Some(TrustUntrustStatus::AllowAlways);
        }

        let workspace = crate::find_workspace().0;

        self.0.get(&workspace).copied()
    }

    fn write_trust_to_file(&self) {
        let mut trust_text = String::new();
        for (workspace, trust) in self.0.iter() {
            if let TrustUntrustStatus::AllowAlways = trust {
                if let Some(path_str) = workspace.to_str() {
                    trust_text += &format!("{path_str}\n");
                }
            }
        }
        if let Ok(false) = fs::exists(data_dir()) {
            if let Err(e) = fs::create_dir_all(data_dir()) {
                log::error!("Couldn't create helix's data directory: {:?}", e);
            };
        }
        if let Err(e) = fs::write(workspace_trust_file(), trust_text) {
            log::error!("Error during write of workspace_trust file: {:?}", e);
        }
    }

    fn write_exclusion_to_file(&self) {
        let mut exclude_text = String::new();
        for (workspace, trust) in self.0.iter() {
            if let TrustUntrustStatus::DenyAlways = trust {
                if let Some(path_str) = workspace.to_str() {
                    exclude_text += &format!("{path_str}\n");
                }
            }
        }
        if let Ok(false) = fs::exists(data_dir()) {
            if let Err(e) = fs::create_dir_all(data_dir()) {
                log::error!("Couldn't create helix's data directory: {:?}", e);
            };
        }
        if let Err(e) = fs::write(workspace_exclude_file(), exclude_text) {
            log::error!("Error during write of workspace_trust file: {:?}", e);
        }
    }

    /// Mark current workspace trusted
    pub fn trust_workspace(&mut self) {
        let workspace = crate::find_workspace().0;
        self.0.insert(workspace, TrustUntrustStatus::AllowAlways);
        self.write_trust_to_file();
    }

    /// Remove trusted mark from current workspace
    pub fn untrust_workspace(&mut self) {
        let workspace = crate::find_workspace().0;
        self.0.insert(workspace, TrustUntrustStatus::DenyOnce);
        self.write_trust_to_file();
    }

    /// Mark current workspace excluded.
    pub fn exclude_workspace(&mut self) {
        let workspace = crate::find_workspace().0;
        self.0.insert(workspace, TrustUntrustStatus::DenyAlways);
        self.write_exclusion_to_file();
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub enum TrustUntrustStatus {
    DenyAlways,
    #[default]
    DenyOnce,
    AllowAlways,
}

/// Should be used only when there is no `Editor` available.
pub fn quick_query_workspace(insecure: bool) -> TrustStatus {
    if insecure {
        return TrustStatus::Trusted;
    }

    let workspace = crate::find_workspace().0;
    match fs::read_to_string(workspace_trust_file()) {
        Ok(workspace_trust_file) => {
            for line in workspace_trust_file.split('\n') {
                if PathBuf::from(line) == workspace {
                    return TrustStatus::Trusted;
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
        Err(err) => log::error!("workspace file couldn't be read: {err:?}"),
    };
    TrustStatus::Untrusted
}
