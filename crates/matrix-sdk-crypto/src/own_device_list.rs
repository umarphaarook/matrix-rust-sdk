// Copyright 2026 Zaure.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Serving the account's secrets only to devices on the signed own-device
//! list.
//!
//! An own device decides who may be handed the account's secrets, and older
//! message keys on request, from the signed list of own devices
//! ([`OwnDeviceList`]). The application reads the list from account data and
//! passes it to [`OlmMachine::receive_own_device_list`](crate::OlmMachine) on
//! every sync, and passes `None` when it is missing. This module remembers
//! what the device has accepted and answers one question for the serving
//! paths: may this device be served?
//!
//! The rule is opt-in and fail-closed:
//!
//! * A device that has never accepted a valid list serves as it always did.
//!   Nothing changes for an account, or an app, that never uses the list.
//! * From the moment it has accepted one, it serves only devices on the most
//!   recent list it has accepted, and only while the list it was last given was
//!   valid.
//! * It remembers the highest version it has accepted and never accepts a lower
//!   one, so a server that deletes, rewinds or rewrites the list can only make
//!   the device stop serving, never serve more.
//!
//! # Which key is trusted
//!
//! A list is checked against the self-signing key of this device's own user
//! identity, and only if that identity is verified. The server supplies the
//! identity, but a server that swaps it flips the device's verification of its
//! own identity off (the master key changes), which stops list checking and
//! serving at once. The remembered version belongs to the self-signing key it
//! was seen under: when the user resets their cross-signing keys and verifies
//! the new identity, lists under the new key start again from version 1.
//! Serving also requires the remembered key to be the current one, so a list
//! signed under a key that has since been replaced serves nobody.

use std::collections::BTreeSet;

use ruma::{DeviceId, OwnedDeviceId};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    OwnUserIdentityData,
    store::{CryptoStoreError, Result, Store},
    types::{OwnDeviceList, OwnDeviceListError},
};

/// The custom-value key under which the remembered list state is stored.
const OWN_DEVICE_LIST_STATE_KEY: &str = "zaure.own_device_list_state";

/// What this device remembers about the own-device list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredState {
    /// The self-signing key (unpadded base64) the remembered version was seen
    /// under.
    self_signing_key: String,

    /// The highest version of a valid list accepted under that key. Only ever
    /// increases while the key stays the same.
    version: u64,

    /// The devices on the list in force: the list of that version, narrowed if
    /// two different lists of the same version were seen.
    devices: BTreeSet<OwnedDeviceId>,

    /// Whether the list this device was last given was valid and not older
    /// than `version`. While `false` nobody is served.
    serving: bool,
}

impl StoredState {
    /// The state of a device whose stored state can not be read: enforcing,
    /// but serving nobody until a valid list is accepted again.
    fn refusing() -> Self {
        Self {
            self_signing_key: String::new(),
            version: 0,
            devices: BTreeSet::new(),
            serving: false,
        }
    }
}

/// The own-device list a device is serving from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnDeviceListStatus {
    /// The highest version of a valid list this device has accepted.
    pub version: u64,

    /// The devices that may be served.
    pub devices: BTreeSet<OwnedDeviceId>,

    /// Whether this device is serving at all right now. It is not when the
    /// list it was last given was missing, invalid or older than one it has
    /// accepted.
    pub serving: bool,
}

/// What [`OlmMachine::receive_own_device_list`](crate::OlmMachine) did with the
/// list it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnDeviceListOutcome {
    /// The list is valid and is now the one this device serves from.
    Accepted {
        /// The version of the accepted list.
        version: u64,
    },

    /// No list was given.
    Missing,

    /// The list was given but is not valid.
    Invalid,

    /// The list is valid but older than one this device has accepted. It is
    /// refused, and so is serving, until a list of at least the highest
    /// version seen is given.
    Rewound {
        /// The highest version this device has accepted.
        seen: u64,

        /// The version of the list that was given.
        got: u64,
    },

    /// This device has no verified own identity to check a list against.
    NoTrustedIdentity,
}

/// What checking a candidate list against our own identity found.
enum Evaluation {
    Missing,
    NoTrustedIdentity,
    Invalid,
    /// The list verifies under this self-signing key (unpadded base64).
    Valid {
        self_signing_key: String,
    },
}

fn self_signing_key_base64(identity: &OwnUserIdentityData) -> Option<String> {
    identity.self_signing_key().get_first_key().map(|key| key.to_base64())
}

impl Store {
    /// The remembered state, or `None` if no valid list was ever accepted.
    ///
    /// A state that exists but can not be decoded counts as an enforcing state
    /// that serves nobody, not as no state: corruption must never switch the
    /// rule off.
    async fn load_own_device_list_state(&self) -> Result<Option<StoredState>> {
        let Some(bytes) = self.get_custom_value(OWN_DEVICE_LIST_STATE_KEY).await? else {
            return Ok(None);
        };

        match rmp_serde::from_slice(&bytes) {
            Ok(state) => Ok(Some(state)),
            Err(error) => {
                error!(%error, "The own-device list state is unreadable, serving nobody");
                Ok(Some(StoredState::refusing()))
            }
        }
    }

    async fn store_own_device_list_state(&self, state: &StoredState) -> Result<()> {
        self.set_value(OWN_DEVICE_LIST_STATE_KEY, state).await
    }

    /// Our own identity, if we have verified it.
    async fn verified_own_identity(&self) -> Result<Option<OwnUserIdentityData>> {
        Ok(self
            .get_user_identity(self.user_id())
            .await?
            .and_then(|identity| identity.into_own())
            .filter(|identity| identity.is_verified()))
    }

    /// The own-device list this device is serving from, if it has accepted
    /// one.
    pub async fn own_device_list_status(&self) -> Result<Option<OwnDeviceListStatus>> {
        Ok(self.load_own_device_list_state().await?.map(|state| OwnDeviceListStatus {
            version: state.version,
            devices: state.devices,
            serving: state.serving,
        }))
    }

    /// The highest version this device has accepted under our current
    /// self-signing key, if it has accepted one.
    ///
    /// A new list has to be above this to be accepted, here and by the other
    /// devices that saw the same lists.
    pub(crate) async fn highest_accepted_own_device_list_version(&self) -> Result<Option<u64>> {
        let Some(state) = self.load_own_device_list_state().await? else {
            return Ok(None);
        };

        let current_key = self
            .get_user_identity(self.user_id())
            .await?
            .and_then(|identity| identity.into_own())
            .as_ref()
            .and_then(self_signing_key_base64);

        Ok((current_key.as_deref() == Some(state.self_signing_key.as_str()))
            .then_some(state.version))
    }

    /// May the account's secrets, and older message keys, be handed to
    /// `device_id`, a device of this user that we already verified?
    ///
    /// `true` if no valid list has ever been accepted (nothing is enforced),
    /// otherwise only if the list in force names the device, the last list we
    /// were given was valid, and it was signed by the self-signing key of our
    /// current, verified identity. Any failure to find out refuses.
    pub(crate) async fn own_device_list_permits(&self, device_id: &DeviceId) -> bool {
        match self.own_device_list_permits_inner(device_id).await {
            Ok(permitted) => permitted,
            Err(error) => {
                error!(%error, "Can't read the own-device list state, not serving the device");
                false
            }
        }
    }

    async fn own_device_list_permits_inner(&self, device_id: &DeviceId) -> Result<bool> {
        let Some(state) = self.load_own_device_list_state().await? else {
            return Ok(true);
        };

        if !state.serving || !state.devices.contains(device_id) {
            return Ok(false);
        }

        // The list was signed by the key we remember; it only counts while
        // that is still the self-signing key of our verified identity.
        let current_key =
            self.verified_own_identity().await?.as_ref().and_then(self_signing_key_base64);

        Ok(current_key.as_deref() == Some(state.self_signing_key.as_str()))
    }

    /// Process the own-device list as the application last read it.
    pub(crate) async fn receive_own_device_list(
        &self,
        candidate: Option<&OwnDeviceList>,
    ) -> std::result::Result<OwnDeviceListOutcome, CryptoStoreError> {
        let _guard = self.own_device_list_lock().lock().await;

        let current = self.load_own_device_list_state().await?;
        let evaluation = self.evaluate_own_device_list(candidate).await?;

        let (outcome, new_state) = match (evaluation, candidate) {
            (Evaluation::Valid { self_signing_key }, Some(list)) => {
                Self::decide(current.as_ref(), self_signing_key, list)
            }
            (Evaluation::Missing, _) => (OwnDeviceListOutcome::Missing, None),
            (Evaluation::NoTrustedIdentity, _) => (OwnDeviceListOutcome::NoTrustedIdentity, None),
            (Evaluation::Invalid, _) | (Evaluation::Valid { .. }, None) => {
                (OwnDeviceListOutcome::Invalid, None)
            }
        };

        // `new_state` is `None` when the candidate was not usable: once a list
        // has been accepted, stop serving until a usable one is seen. Before
        // that there is nothing to stop.
        let new_state = new_state.or_else(|| {
            current.clone().map(|state| {
                if state.serving {
                    warn!(?outcome, "The own-device list is not usable, no longer serving");
                }
                StoredState { serving: false, ..state }
            })
        });

        if let Some(new_state) = new_state
            && current.as_ref() != Some(&new_state)
        {
            self.store_own_device_list_state(&new_state).await?;
        }

        Ok(outcome)
    }

    /// Decide what a candidate that verified does to the remembered state.
    ///
    /// Returns the outcome, and the state to keep if the candidate was
    /// usable. `None` means the candidate was refused.
    fn decide(
        current: Option<&StoredState>,
        self_signing_key: String,
        list: &OwnDeviceList,
    ) -> (OwnDeviceListOutcome, Option<StoredState>) {
        let accepted = OwnDeviceListOutcome::Accepted { version: list.version() };
        let fresh = |devices: BTreeSet<OwnedDeviceId>| StoredState {
            self_signing_key: self_signing_key.clone(),
            version: list.version(),
            devices,
            serving: true,
        };

        match current {
            // The first valid list: enforcement starts here.
            None => (accepted, Some(fresh(list.devices().clone()))),

            // The user's cross-signing keys were replaced and the new identity
            // verified: versions start again under the new key. The old key's
            // lists can not be replayed, they no longer verify.
            Some(state) if state.self_signing_key != self_signing_key => {
                (accepted, Some(fresh(list.devices().clone())))
            }

            // Newer: it replaces what we have.
            Some(state) if list.version() > state.version => {
                (accepted, Some(fresh(list.devices().clone())))
            }

            // The same version again, e.g. after a deletion. Two own devices
            // that wrote the same version at once leave two valid lists of one
            // version; serve only what both name, until a higher version
            // merges them. This only ever narrows.
            Some(state) if list.version() == state.version => {
                let devices = state.devices.intersection(list.devices()).cloned().collect();
                (accepted, Some(fresh(devices)))
            }

            // Older than one we accepted: a rewind.
            Some(state) => {
                (OwnDeviceListOutcome::Rewound { seen: state.version, got: list.version() }, None)
            }
        }
    }

    async fn evaluate_own_device_list(
        &self,
        candidate: Option<&OwnDeviceList>,
    ) -> std::result::Result<Evaluation, CryptoStoreError> {
        let Some(list) = candidate else {
            return Ok(Evaluation::Missing);
        };

        // The list is checked against the self-signing key of our own
        // identity, and only if we have verified that identity: the server
        // supplies the identity, so an unverified one proves nothing.
        let Some(own_identity) = self.verified_own_identity().await? else {
            return Ok(Evaluation::NoTrustedIdentity);
        };

        match list.verify(own_identity.self_signing_key()) {
            Ok(()) => match self_signing_key_base64(&own_identity) {
                Some(self_signing_key) => {
                    info!(version = list.version(), "The own-device list is valid");
                    Ok(Evaluation::Valid { self_signing_key })
                }
                None => Ok(Evaluation::Invalid),
            },
            Err(OwnDeviceListError::Store(error)) => Err(error),
            Err(error) => {
                warn!(%error, "The own-device list is not valid");
                Ok(Evaluation::Invalid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use assert_matches2::assert_matches;
    use matrix_sdk_test::async_test;
    use ruma::{DeviceId, OwnedDeviceId, device_id, user_id};
    use serde_json::json;

    use super::{OWN_DEVICE_LIST_STATE_KEY, OwnDeviceListOutcome};
    use crate::{
        OlmMachine, OlmMachineBuilder,
        olm::PrivateCrossSigningIdentity,
        store::MemoryStore,
        types::{OwnDeviceList, OwnDeviceListError},
    };

    // `device_id!` is not usable in a `const`, so these are small functions
    // named like constants.
    #[allow(non_snake_case)]
    fn A() -> &'static DeviceId {
        device_id!("DEVICEA")
    }
    #[allow(non_snake_case)]
    fn B() -> &'static DeviceId {
        device_id!("DEVICEB")
    }
    #[allow(non_snake_case)]
    fn C() -> &'static DeviceId {
        device_id!("DEVICEC")
    }

    fn set(ids: &[&DeviceId]) -> BTreeSet<OwnedDeviceId> {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    /// An own device that holds the account's secrets and has verified its own
    /// identity.
    async fn own_machine() -> OlmMachine {
        let machine = OlmMachine::new(user_id!("@alice:example.org"), A()).await;
        machine.bootstrap_cross_signing(false).await.unwrap();
        machine
    }

    async fn permits(machine: &OlmMachine, device: &DeviceId) -> bool {
        machine.store().own_device_list_permits(device).await
    }

    #[async_test]
    async fn test_nothing_is_enforced_until_a_valid_list_is_accepted() {
        let machine = own_machine().await;

        assert_eq!(machine.own_device_list_status().await.unwrap(), None);
        assert!(permits(&machine, B()).await);

        // A missing list, and a list that does not verify, change nothing for
        // a device that has never accepted one.
        assert_eq!(
            machine.receive_own_device_list(None).await.unwrap(),
            OwnDeviceListOutcome::Missing
        );
        let other = PrivateCrossSigningIdentity::new(machine.user_id().to_owned());
        let mut forged = OwnDeviceList::new(machine.user_id().to_owned(), 1, set(&[C()]));
        other.sign_own_device_list(&mut forged).await.unwrap();
        assert_eq!(
            machine.receive_own_device_list(Some(&forged)).await.unwrap(),
            OwnDeviceListOutcome::Invalid
        );

        assert_eq!(machine.own_device_list_status().await.unwrap(), None);
        assert!(permits(&machine, B()).await);
        assert!(permits(&machine, C()).await);
    }

    #[async_test]
    async fn test_a_valid_list_starts_enforcement() {
        let machine = own_machine().await;
        let list = machine.sign_own_device_list(1, set(&[A(), B()])).await.unwrap();

        assert_eq!(
            machine.receive_own_device_list(Some(&list)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 1 }
        );

        let status = machine.own_device_list_status().await.unwrap().unwrap();
        assert_eq!((status.version, status.devices, status.serving), (1, set(&[A(), B()]), true));
        assert!(permits(&machine, A()).await);
        assert!(permits(&machine, B()).await);
        assert!(!permits(&machine, C()).await);
    }

    #[async_test]
    async fn test_a_deleted_list_stops_serving_until_it_reappears() {
        let machine = own_machine().await;
        let list = machine.sign_own_device_list(1, set(&[A(), B()])).await.unwrap();
        machine.receive_own_device_list(Some(&list)).await.unwrap();
        assert!(permits(&machine, B()).await);

        // The server removes the list.
        assert_eq!(
            machine.receive_own_device_list(None).await.unwrap(),
            OwnDeviceListOutcome::Missing
        );
        assert!(!permits(&machine, A()).await);
        assert!(!permits(&machine, B()).await);
        assert!(!permits(&machine, C()).await);
        let status = machine.own_device_list_status().await.unwrap().unwrap();
        assert!(!status.serving);
        assert_eq!(status.version, 1, "the remembered version survives the deletion");

        // The same version, valid, serves again.
        assert_eq!(
            machine.receive_own_device_list(Some(&list)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 1 }
        );
        assert!(permits(&machine, B()).await);
        assert!(!permits(&machine, C()).await);
    }

    #[async_test]
    async fn test_a_rewound_list_is_refused_and_a_removed_device_stays_refused() {
        let machine = own_machine().await;

        // Version 1 names B. Version 2, signed later, removes it.
        let v1 = machine.sign_own_device_list(1, set(&[A(), B()])).await.unwrap();
        machine.receive_own_device_list(Some(&v1)).await.unwrap();
        let v2 = machine.sign_own_device_list(2, set(&[A()])).await.unwrap();
        machine.receive_own_device_list(Some(&v2)).await.unwrap();
        assert!(permits(&machine, A()).await);
        assert!(!permits(&machine, B()).await);

        // The server presents version 1 again. It is genuinely signed, and it
        // still lists B.
        assert_eq!(
            machine.receive_own_device_list(Some(&v1)).await.unwrap(),
            OwnDeviceListOutcome::Rewound { seen: 2, got: 1 }
        );
        assert!(!permits(&machine, B()).await, "the removed device must not come back");
        assert!(!permits(&machine, A()).await, "nobody is served off a rewound list");
        assert_eq!(machine.own_device_list_status().await.unwrap().unwrap().version, 2);

        // The current list restores serving, and B is still refused.
        machine.receive_own_device_list(Some(&v2)).await.unwrap();
        assert!(permits(&machine, A()).await);
        assert!(!permits(&machine, B()).await);
    }

    #[async_test]
    async fn test_a_forged_or_wrongly_signed_list_is_invalid_and_stops_serving() {
        let machine = own_machine().await;
        let list = machine.sign_own_device_list(1, set(&[A()])).await.unwrap();
        machine.receive_own_device_list(Some(&list)).await.unwrap();
        assert!(permits(&machine, A()).await);

        // Altered after signing: a device added and the version raised.
        let mut json = serde_json::to_value(&list).unwrap();
        json["devices"] = json!(["DEVICEA", "DEVICEC"]);
        json["version"] = json!(2);
        let forged: OwnDeviceList = serde_json::from_value(json).unwrap();

        assert_eq!(
            machine.receive_own_device_list(Some(&forged)).await.unwrap(),
            OwnDeviceListOutcome::Invalid
        );
        assert!(!permits(&machine, C()).await);
        assert!(!permits(&machine, A()).await);
        assert_eq!(machine.own_device_list_status().await.unwrap().unwrap().version, 1);

        // Signed with another identity's self-signing key: what a borrowed
        // device or the server could make.
        let other = PrivateCrossSigningIdentity::new(machine.user_id().to_owned());
        let mut wrong = OwnDeviceList::new(machine.user_id().to_owned(), 5, set(&[A(), C()]));
        other.sign_own_device_list(&mut wrong).await.unwrap();
        assert_eq!(
            machine.receive_own_device_list(Some(&wrong)).await.unwrap(),
            OwnDeviceListOutcome::Invalid
        );
        assert!(!permits(&machine, C()).await);

        // Neither raised the remembered version, so the real list still works.
        assert_eq!(machine.own_device_list_status().await.unwrap().unwrap().version, 1);
        machine.receive_own_device_list(Some(&list)).await.unwrap();
        assert!(permits(&machine, A()).await);
        assert!(!permits(&machine, C()).await);
    }

    #[async_test]
    async fn test_an_unverified_own_identity_accepts_no_list() {
        let machine = own_machine().await;
        let list = machine.sign_own_device_list(1, set(&[A(), B()])).await.unwrap();

        // Not verified (the server could have swapped the identity).
        let identity = machine
            .store()
            .get_user_identity(machine.user_id())
            .await
            .unwrap()
            .unwrap()
            .into_own()
            .unwrap();
        identity.mark_as_unverified();
        machine
            .store()
            .save_changes(crate::store::types::Changes {
                identities: crate::store::types::IdentityChanges {
                    changed: vec![identity.clone().into()],
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(
            machine.receive_own_device_list(Some(&list)).await.unwrap(),
            OwnDeviceListOutcome::NoTrustedIdentity
        );
        assert_eq!(machine.own_device_list_status().await.unwrap(), None);

        // Having accepted a list, losing the verification stops serving at
        // once, with no further list needed.
        identity.mark_as_verified();
        machine
            .store()
            .save_changes(crate::store::types::Changes {
                identities: crate::store::types::IdentityChanges {
                    changed: vec![identity.clone().into()],
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .unwrap();
        machine.receive_own_device_list(Some(&list)).await.unwrap();
        assert!(permits(&machine, B()).await);

        identity.mark_as_unverified();
        machine
            .store()
            .save_changes(crate::store::types::Changes {
                identities: crate::store::types::IdentityChanges {
                    changed: vec![identity.into()],
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(!permits(&machine, B()).await);
    }

    #[async_test]
    async fn test_replacing_the_cross_signing_keys_restarts_the_versions() {
        let machine = own_machine().await;
        let old = machine.sign_own_device_list(5, set(&[A(), B()])).await.unwrap();
        machine.receive_own_device_list(Some(&old)).await.unwrap();
        assert!(permits(&machine, B()).await);

        // The user starts fresh: new cross-signing keys, which this device
        // holds and has verified.
        machine.bootstrap_cross_signing(true).await.unwrap();

        // The list under the old key serves nobody, and can not be replayed.
        assert!(!permits(&machine, B()).await);
        assert_eq!(
            machine.receive_own_device_list(Some(&old)).await.unwrap(),
            OwnDeviceListOutcome::Invalid
        );

        // A list under the new key may start again from version 1, which is
        // below 5, because the remembered version belongs to the old key.
        let fresh = machine.sign_own_device_list(1, set(&[A()])).await.unwrap();
        assert_eq!(
            machine.receive_own_device_list(Some(&fresh)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 1 }
        );
        assert!(permits(&machine, A()).await);
        assert!(!permits(&machine, B()).await);
    }

    #[async_test]
    async fn test_two_lists_of_one_version_serve_only_what_both_name() {
        let machine = own_machine().await;

        // Two own devices each added a device to version 2 at the same time.
        let base = machine.sign_own_device_list(1, set(&[A()])).await.unwrap();
        machine.receive_own_device_list(Some(&base)).await.unwrap();
        let with_b = machine.sign_own_device_list(2, set(&[A(), B()])).await.unwrap();
        let with_c = {
            // Signed at the same version by "the other device".
            let mut list = OwnDeviceList::new(machine.user_id().to_owned(), 2, set(&[A(), C()]));
            let identity = machine.store().private_identity();
            identity.lock().await.sign_own_device_list(&mut list).await.unwrap();
            list
        };

        machine.receive_own_device_list(Some(&with_b)).await.unwrap();
        assert!(permits(&machine, B()).await);

        assert_eq!(
            machine.receive_own_device_list(Some(&with_c)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 2 }
        );
        assert!(permits(&machine, A()).await);
        assert!(!permits(&machine, B()).await);
        assert!(!permits(&machine, C()).await);

        // The merged list at version 3 serves both.
        let merged = machine.sign_own_device_list(3, set(&[A(), B(), C()])).await.unwrap();
        machine.receive_own_device_list(Some(&merged)).await.unwrap();
        assert!(permits(&machine, B()).await);
        assert!(permits(&machine, C()).await);
    }

    #[async_test]
    async fn test_the_remembered_version_survives_a_restart() {
        let store = Arc::new(MemoryStore::new());
        let build = || async {
            OlmMachineBuilder::new(user_id!("@alice:example.org"), A())
                .with_crypto_store(store.clone())
                .build()
                .await
                .unwrap()
        };

        let machine = build().await;
        machine.bootstrap_cross_signing(false).await.unwrap();
        let v1 = machine.sign_own_device_list(1, set(&[A(), B()])).await.unwrap();
        machine.receive_own_device_list(Some(&v1)).await.unwrap();
        let v2 = machine.sign_own_device_list(2, set(&[A()])).await.unwrap();
        machine.receive_own_device_list(Some(&v2)).await.unwrap();
        drop(machine);

        let machine = build().await;
        let status = machine.own_device_list_status().await.unwrap().unwrap();
        assert_eq!((status.version, status.serving), (2, true));
        assert!(permits(&machine, A()).await);
        assert!(!permits(&machine, B()).await);

        // The rewind is still a rewind after the restart.
        assert_eq!(
            machine.receive_own_device_list(Some(&v1)).await.unwrap(),
            OwnDeviceListOutcome::Rewound { seen: 2, got: 1 }
        );
    }

    #[async_test]
    async fn test_an_unreadable_state_refuses_rather_than_enforcing_nothing() {
        let machine = own_machine().await;
        machine
            .store()
            .set_custom_value(OWN_DEVICE_LIST_STATE_KEY, b"not a state".to_vec())
            .await
            .unwrap();

        assert!(!permits(&machine, A()).await);
        assert!(!permits(&machine, B()).await);

        // A valid list repairs it.
        let list = machine.sign_own_device_list(1, set(&[A(), B()])).await.unwrap();
        assert_eq!(
            machine.receive_own_device_list(Some(&list)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 1 }
        );
        assert!(permits(&machine, B()).await);
    }

    #[async_test]
    async fn test_concurrent_updates_never_lower_the_remembered_version() {
        let machine = own_machine().await;
        let v1 = machine.sign_own_device_list(1, set(&[A()])).await.unwrap();
        let v2 = machine.sign_own_device_list(2, set(&[A(), B()])).await.unwrap();

        let (one, two) = futures_util::future::join(
            machine.receive_own_device_list(Some(&v2)),
            machine.receive_own_device_list(Some(&v1)),
        )
        .await;
        one.unwrap();
        two.unwrap();

        // Whichever ran first, the version-1 call can not have lowered the
        // version-2 one.
        let status = machine.own_device_list_status().await.unwrap().unwrap();
        assert_eq!(status.version, 2);
    }

    #[async_test]
    async fn test_signing_refuses_a_version_that_would_be_refused() {
        let machine = own_machine().await;
        let list = machine.sign_own_device_list(4, set(&[A()])).await.unwrap();
        machine.receive_own_device_list(Some(&list)).await.unwrap();

        for version in [1, 4] {
            assert_matches!(
                machine.sign_own_device_list(version, set(&[A()])).await,
                Err(OwnDeviceListError::VersionNotAboveSeen { seen: 4, requested })
            );
            assert_eq!(requested, version);
        }
        machine.sign_own_device_list(5, set(&[A()])).await.unwrap();
    }
}
