use std::{fmt, path::PathBuf, sync::Arc};

use serde::Serialize;

use crate::{
    FileSecretBackend, Result, RuntimeProfile, SecretBackend, SecretBackendError,
    SecretBackendSecurity,
};

/// Narrow injection point for an OS keychain, HSM, or separately reviewed
/// remote secret service. Implementations must return a production-classified
/// backend; the factory verifies this before releasing it to signing code.
pub trait ProductionSecretBackendResolver: Send + Sync {
    fn resolve(&self) -> Result<Arc<dyn SecretBackend>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretBackendMode {
    Production,
    SelfHostedDevelopment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SecretBackendPublicStatus {
    pub mode: SecretBackendMode,
    pub configured: bool,
}

enum SecretBackendSelection {
    Production,
    SelfHostedDevelopment { root: PathBuf },
}

/// Resolves the signing secret backend under one explicit runtime policy.
///
/// Production has no built-in fallback. Self-hosted development is a separate
/// constructor so a caller must opt in at its configuration boundary.
pub struct SecretBackendFactory {
    selection: SecretBackendSelection,
    production_resolver: Option<Arc<dyn ProductionSecretBackendResolver>>,
}

impl SecretBackendFactory {
    pub fn production() -> Self {
        Self {
            selection: SecretBackendSelection::Production,
            production_resolver: None,
        }
    }

    pub fn self_hosted_development(root: impl Into<PathBuf>) -> Self {
        Self {
            selection: SecretBackendSelection::SelfHostedDevelopment { root: root.into() },
            production_resolver: None,
        }
    }

    pub fn with_production_resolver(
        mut self,
        resolver: Arc<dyn ProductionSecretBackendResolver>,
    ) -> Self {
        self.production_resolver = Some(resolver);
        self
    }

    pub fn resolve(&self) -> Result<Arc<dyn SecretBackend>> {
        match &self.selection {
            SecretBackendSelection::Production => {
                let resolver = self
                    .production_resolver
                    .as_ref()
                    .ok_or(SecretBackendError::ProductionBackendUnavailable)?;
                let backend = resolver
                    .resolve()
                    .map_err(|_| SecretBackendError::ProductionBackendResolutionFailed)?;
                if backend.security() != SecretBackendSecurity::Production {
                    return Err(SecretBackendError::DevelopmentBackendForbidden);
                }
                Ok(backend)
            }
            SecretBackendSelection::SelfHostedDevelopment { root } => Ok(Arc::new(
                FileSecretBackend::open(root, RuntimeProfile::Development)?,
            )),
        }
    }

    pub fn public_status(&self) -> SecretBackendPublicStatus {
        match self.selection {
            SecretBackendSelection::Production => SecretBackendPublicStatus {
                mode: SecretBackendMode::Production,
                configured: self.production_resolver.is_some(),
            },
            SecretBackendSelection::SelfHostedDevelopment { .. } => SecretBackendPublicStatus {
                mode: SecretBackendMode::SelfHostedDevelopment,
                configured: true,
            },
        }
    }
}

impl fmt::Debug for SecretBackendFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBackendFactory")
            .field("public_status", &self.public_status())
            .finish()
    }
}
