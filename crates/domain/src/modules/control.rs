//! Device-local intent and admission, separate from provider observations.
//! NDS consent never grants operating-system or browser permissions.
use crate::{
    ModuleKind, Permission, devices::ControlMode, modules::ModuleObservation, state::Reachability,
};
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

    /// Effective admission under the device's authenticated control mode
    /// (ADR 0018). Fullauto admits a supported, installed system tool without
    /// the consent checklist; actual OS/provider restrictions still apply at
    /// I/O. Manual keeps this configuration. Functional modules keep their
    /// explicit configuration until their own control increment.
    pub fn admit_in(
        &self,
        mode: ControlMode,
        kind: ModuleKind,
        supported: bool,
        installed: bool,
        required: &BTreeSet<Permission>,
    ) -> Result<(), Readiness> {
        match (mode, kind) {
            (ControlMode::Fullauto, ModuleKind::Tool) => {
                if !supported {
                    Err(Readiness::Unsupported)
                } else if !installed {
                    Err(Readiness::NotInstalled)
                } else {
                    Ok(())
                }
            }
            _ => self.admit(supported, installed, required),
        }
    }

    pub fn readiness(
        &self,
        supported: bool,
        installed: bool,
        required: &BTreeSet<Permission>,
        observation: Option<&ModuleObservation>,
    ) -> Readiness {
        self.readiness_in(
            ControlMode::Manual,
            ModuleKind::Integration,
            supported,
            installed,
            required,
            observation,
        )
    }

    pub fn readiness_in(
        &self,
        mode: ControlMode,
        kind: ModuleKind,
        supported: bool,
        installed: bool,
        required: &BTreeSet<Permission>,
        observation: Option<&ModuleObservation>,
    ) -> Readiness {
        if let Err(reason) = self.admit_in(mode, kind, supported, installed, required) {
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
    fn browser_control_requires_explicit_permission_without_claiming_readiness() {
        let required = BTreeSet::from([Permission::BrowserControl]);
        assert_eq!(
            Configuration::default().admit(true, true, &required),
            Err(Readiness::Disabled)
        );
        for permissions in [
            BTreeSet::new(),
            BTreeSet::from([Permission::ReadOnly]),
            BTreeSet::from([Permission::Clipboard]),
            BTreeSet::from([Permission::ReadOnly, Permission::Clipboard]),
        ] {
            let value = Configuration {
                enabled: true,
                permissions,
            };
            assert_eq!(
                value.admit(true, true, &required),
                Err(Readiness::PermissionRequired)
            );
        }
        let value = Configuration {
            enabled: true,
            permissions: required.clone(),
        };
        assert_eq!(value.admit(true, true, &required), Ok(()));
        assert_eq!(
            value.readiness(true, true, &required, None),
            Readiness::NotChecked
        );
    }

    #[test]
    fn browser_revocation_and_disable_override_a_previous_ready_observation() {
        let required = BTreeSet::from([Permission::BrowserControl]);
        let mut value = Configuration {
            enabled: true,
            permissions: BTreeSet::from([
                Permission::BrowserControl,
                Permission::ReadOnly,
                Permission::Clipboard,
            ]),
        };
        let mut observed = observation();
        observed.id = "browser-use".into();
        assert_eq!(
            value.readiness(true, true, &required, Some(&observed)),
            Readiness::Ready
        );
        value.permissions.remove(&Permission::BrowserControl);
        assert_eq!(
            value.readiness(true, true, &required, Some(&observed)),
            Readiness::PermissionRequired
        );
        value.permissions.insert(Permission::BrowserControl);
        value.enabled = false;
        assert_eq!(
            value.readiness(true, true, &required, Some(&observed)),
            Readiness::Disabled
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
    fn fullauto_admits_installed_tools_without_the_checklist_but_not_functional_modules() {
        let required = BTreeSet::from([Permission::Clipboard]);
        let unset = Configuration::default();
        let tool = ModuleKind::Tool;
        assert_eq!(
            unset.admit_in(ControlMode::Fullauto, tool, true, true, &required),
            Ok(())
        );
        assert_eq!(
            unset.admit_in(ControlMode::Fullauto, tool, true, false, &required),
            Err(Readiness::NotInstalled)
        );
        assert_eq!(
            unset.admit_in(ControlMode::Fullauto, tool, false, true, &required),
            Err(Readiness::Unsupported)
        );
        // Manual keeps every existing explicit restriction.
        assert_eq!(
            unset.admit_in(ControlMode::Manual, tool, true, true, &required),
            Err(Readiness::Disabled)
        );
        let enabled = Configuration {
            enabled: true,
            permissions: BTreeSet::new(),
        };
        assert_eq!(
            enabled.admit_in(ControlMode::Manual, tool, true, true, &required),
            Err(Readiness::PermissionRequired)
        );
        // Git write, browser control and remote display keep explicit consent.
        for kind in [ModuleKind::Gds, ModuleKind::Rds, ModuleKind::Integration] {
            assert_eq!(
                unset.admit_in(ControlMode::Fullauto, kind, true, true, &required),
                Err(Readiness::Disabled)
            );
        }
        let mut observed = observation();
        observed.id = "sysinfo".into();
        assert_eq!(
            unset.readiness_in(
                ControlMode::Fullauto,
                tool,
                true,
                true,
                &required,
                Some(&observed)
            ),
            Readiness::Ready
        );
        assert_eq!(
            unset.readiness_in(
                ControlMode::Manual,
                tool,
                true,
                true,
                &required,
                Some(&observed)
            ),
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
