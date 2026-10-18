//! Device-local intent and admission, separate from provider observations.
//! NDS consent never grants operating-system or browser permissions.
use crate::{Permission, modules::ModuleObservation, state::Reachability};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub enabled: bool,
    pub permissions: BTreeSet<Permission>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Disabled,
    Unsupported,
    NotInstalled,
    PermissionRequired,
    NotChecked,
    Ready,
    Unavailable,
    Failed,
}

impl Configuration {
    /// Adapter requirements describe the operation actually available in this
    /// composition, not every permission a provider might need elsewhere.
    /// A successful decision permits attempting I/O; it does not prove success.
    pub fn admit(
        &self,
        supported: bool,
        installed: bool,
        required: &BTreeSet<Permission>,
    ) -> Result<(), Readiness> {
        if !supported {
            Err(Readiness::Unsupported)
        } else if !self.enabled {
            Err(Readiness::Disabled)
        } else if !installed {
            Err(Readiness::NotInstalled)
        } else if !required.is_subset(&self.permissions) {
            Err(Readiness::PermissionRequired)
        } else {
            Ok(())
        }
    }

    pub fn readiness(
        &self,
        supported: bool,
        installed: bool,
        required: &BTreeSet<Permission>,
        observation: Option<&ModuleObservation>,
    ) -> Readiness {
        if let Err(reason) = self.admit(supported, installed, required) {
            return reason;
        }
        let Some(value) = observation.filter(|value| {
            value.configured
                && value.observed_at_ms.is_some_and(|at| at > 0)
                && value.error.is_none()
        }) else {
            return match observation.map(|value| value.reachability) {
                Some(Reachability::Unavailable) => Readiness::Unavailable,
                Some(Reachability::Failed) => Readiness::Failed,
                _ => Readiness::NotChecked,
            };
        };
        match value.reachability {
            Reachability::NotChecked => Readiness::NotChecked,
            Reachability::Reachable => Readiness::Ready,
            Reachability::Unavailable => Readiness::Unavailable,
            Reachability::Failed => Readiness::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::ModuleError;

    fn observation() -> ModuleObservation {
        ModuleObservation {
            id: "clipboard".into(),
            version: "1".into(),
            configured: true,
            reachability: Reachability::Reachable,
            observed_at_ms: Some(100),
            error: None,
        }
    }

    #[test]
    fn enabling_without_permission_or_provider_does_not_authorize_io() {
        let required = BTreeSet::from([Permission::Clipboard]);
        let mut value = Configuration::default();
        assert_eq!(value.admit(true, true, &required), Err(Readiness::Disabled));
        value.enabled = true;
        assert_eq!(
            value.admit(true, true, &required),
            Err(Readiness::PermissionRequired)
        );
        value.permissions.insert(Permission::ReadOnly);
        assert_eq!(
            value.admit(true, true, &required),
            Err(Readiness::PermissionRequired)
        );
        value.permissions.insert(Permission::Clipboard);
        assert_eq!(value.admit(true, true, &required), Ok(()));
        assert_eq!(
            value.admit(true, false, &required),
            Err(Readiness::NotInstalled)
        );
        assert_eq!(
            value.admit(false, true, &required),
            Err(Readiness::Unsupported)
        );
    }

    #[test]
    fn permission_removal_and_disable_override_previous_success() {
        let required = BTreeSet::from([Permission::Clipboard]);
        let mut value = Configuration {
            enabled: true,
            permissions: required.clone(),
        };
        let observed = observation();
        assert_eq!(
            value.readiness(true, true, &required, Some(&observed)),
            Readiness::Ready
        );
        value.permissions.clear();
        assert_eq!(
            value.readiness(true, true, &required, Some(&observed)),
            Readiness::PermissionRequired
        );
        value.enabled = false;
        assert_eq!(
            value.readiness(true, true, &required, Some(&observed)),
            Readiness::Disabled
        );
    }

    #[test]
    fn declaration_and_consent_do_not_establish_actual_readiness() {
        let value = Configuration {
            enabled: true,
            permissions: BTreeSet::new(),
        };
        let required = BTreeSet::new();
        assert_eq!(
            value.readiness(true, true, &required, None),
            Readiness::NotChecked
        );
        let mut observed = observation();
        observed.observed_at_ms = None;
        assert_eq!(
            value.readiness(true, true, &required, Some(&observed)),
            Readiness::NotChecked
        );
        observed.observed_at_ms = Some(100);
        observed.reachability = Reachability::Failed;
        observed.error = Some(ModuleError::ProviderFailed);
        assert_eq!(
            value.readiness(true, true, &required, Some(&observed)),
            Readiness::Failed
        );
    }
}
