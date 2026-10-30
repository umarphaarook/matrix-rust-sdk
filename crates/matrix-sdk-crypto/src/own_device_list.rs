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
//! was seen under. When the user resets their cross-signing keys, lists under
//! the new key are accepted only if the new master key was signed by a device
//! on the last list this device accepted (or after the application adopts the
//! new identity), and the application keeps numbering above the version floor.
//! Serving also requires the remembered key to be the current one, so a list
//! signed under a key that has since been replaced serves nobody.
//!
//! A list is accepted only if it names this very device, with this device's
//! own Ed25519 key. A list that leaves this device out means it was removed,
//! and it serves nobody. That also pins the first list a new device accepts:
//! a list from before the device existed can not name its key.

use std::collections::BTreeMap;

use ruma::{DeviceId, DeviceKeyAlgorithm, DeviceKeyId, OwnedDeviceId};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use vodozemac::Ed25519PublicKey;

use crate::{
    OwnUserIdentityData,
    olm::VerifyJson,
    store::{CryptoStoreError, Result, Store},
    types::{CrossSigningKey, OwnDeviceList, OwnDeviceListError},
};

/// The custom-value key under which the remembered list state is stored.
const OWN_DEVICE_LIST_STATE_KEY: &str = "zaure.own_device_list_state";

/// The custom-value key of the enforcing mode. Present means required.
const OWN_DEVICE_LIST_REQUIRED_KEY: &str = "zaure.own_device_list_required";

/// The custom-value key of the version floor the application set.
const OWN_DEVICE_LIST_FLOOR_KEY: &str = "zaure.own_device_list_floor";

/// What this device remembers about the own-device list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredState {
    /// The self-signing key (unpadded base64) the remembered version was seen
    /// under.
    self_signing_key: String,

    /// The highest version of a valid list accepted under that key. Only ever
    /// increases while the key stays the same.
    version: u64,

    /// The devices on the list in force, with their keys: the list of that
    /// version, narrowed if two different lists of the same version were seen.
    devices: BTreeMap<OwnedDeviceId, Ed25519PublicKey>,

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
            devices: BTreeMap::new(),
            serving: false,
        }
    }

    /// Is this the sentinel for a state that could not be read?
    fn is_unreadable_sentinel(&self) -> bool {
        self.self_signing_key.is_empty()
    }
}

/// The own-device list a device is serving from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnDeviceListStatus {
    /// The highest version of a valid list this device has accepted.
    pub version: u64,

    /// The devices that may be served, with the keys they must present.
    pub devices: BTreeMap<OwnedDeviceId, Ed25519PublicKey>,

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

    /// The list is valid but older than one this device has accepted, or than
    /// the floor the application set. It is refused, and so is serving, until
    /// a list of at least that version is given.
    Rewound {
        /// The version it has to reach: the highest it has accepted, or the
        /// floor the application set, whichever is higher.
        seen: u64,

        /// The version of the list that was given.
        got: u64,
    },

    /// This device has no verified own identity to check a list against.
    NoTrustedIdentity,

    /// The list is valid under a new cross-signing identity, but this device
    /// has no reason to trust that identity: its master key was not signed by
    /// a device on the last list this device accepted. Nothing is served until
    /// the application adopts the new identity
    /// ([`OlmMachine::adopt_own_identity_for_device_list`](crate::OlmMachine)),
    /// which needs this device to hold the identity's private keys.
    NewIdentityNotAnchored,

    /// The list is valid but does not name this device with this device's own
    /// key: this device was removed, or the list is from before it existed.
    /// The version is remembered, but nothing is served.
    ThisDeviceNotListed,

    /// The state this device had remembered can not be read. Nothing is
    /// served, and no list is accepted, until the application adopts the
    /// current identity
    /// ([`OlmMachine::adopt_own_identity_for_device_list`](crate::OlmMachine)),
    /// or the device is set up again.
    StateUnreadable,
}

/// What checking a candidate list against our own identity found.
enum Evaluation {
    Missing,
    NoTrustedIdentity,
    Invalid,
    /// The list verifies under this self-signing key (unpadded base64).
    Valid {
        self_signing_key: String,

        /// Whether our own identity's master key carries a signature from a
        /// device on `current`'s list, matched by key.
        anchored: bool,
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

    /// Has the application made the own-device list required? While it is,
    /// a device that has accepted no list serves nobody.
    pub async fn own_device_list_required(&self) -> Result<bool> {
        Ok(self.get_custom_value(OWN_DEVICE_LIST_REQUIRED_KEY).await?.is_some())
    }

    /// Make the own-device list required, or not.
    ///
    /// Required, a device that has accepted no valid list serves nobody. This
    /// closes the window in which a server that withholds the list keeps a
    /// device serving every verified device of the user. The application sets
    /// it on the first start of a build that supports the list, before the
    /// first sync is processed.
    pub async fn set_own_device_list_required(&self, required: bool) -> Result<()> {
        if required {
            self.set_custom_value(OWN_DEVICE_LIST_REQUIRED_KEY, vec![1]).await
        } else {
            self.remove_custom_value(OWN_DEVICE_LIST_REQUIRED_KEY).await
        }
    }

    /// The version floor the application set, `0` if it set none.
    ///
    /// An unreadable value counts as the highest possible floor, so that
    /// corruption refuses rather than relaxes.
    pub async fn own_device_list_version_floor(&self) -> Result<u64> {
        let Some(bytes) = self.get_custom_value(OWN_DEVICE_LIST_FLOOR_KEY).await? else {
            return Ok(0);
        };

        match rmp_serde::from_slice(&bytes) {
            Ok(floor) => Ok(floor),
            Err(error) => {
                error!(%error, "The own-device list version floor is unreadable, using the maximum");
                Ok(u64::MAX)
            }
        }
    }

    /// Refuse every list below `floor`, and serve nobody off a list below it.
    ///
    /// The floor only ever goes up: a lower value than the one already set is
    /// ignored. The one exception is a stored floor that can not be read
    /// (which counts as the highest possible), which the next call replaces.
    /// The floor is not tied to a self-signing key and is never reset, not
    /// even after the user resets cross-signing: the first list under a new
    /// identity continues the numbering above it. A device that adopts a new
    /// identity and then sees [`OwnDeviceListOutcome::Rewound`] signs a list
    /// at `seen + 1`.
    ///
    /// The application can read the highest version ever signed from secret
    /// storage when a device becomes an own device. Secret storage is not
    /// protected against rollback by the server, so this is defence in depth:
    /// the real guard against a replayed list is that a list has to name this
    /// device's own key.
    pub async fn set_own_device_list_version_floor(&self, floor: u64) -> Result<()> {
        let _guard = self.own_device_list_lock().lock().await;

        let current = match self.get_custom_value(OWN_DEVICE_LIST_FLOOR_KEY).await? {
            None => Some(0u64),
            Some(bytes) => rmp_serde::from_slice::<u64>(&bytes).ok(),
        };
        let floor = current.map_or(floor, |current| current.max(floor));

        self.set_value(OWN_DEVICE_LIST_FLOOR_KEY, &floor).await?;

        // A list below the new floor is out of date: stop serving from it now.
        if let Some(state) = self.load_own_device_list_state().await?
            && state.serving
            && state.version < floor
        {
            self.store_own_device_list_state(&StoredState { serving: false, ..state }).await?;
        }

        Ok(())
    }

    /// Is our own identity the one the remembered list state was accepted
    /// under? `true` when there is no state at all.
    ///
    /// Once a list has been accepted, a different self-signing key means the
    /// identity was replaced and this device has not (yet) anchored the new
    /// one, so nothing signed by the new identity may be trusted on the
    /// strength of the list. Any failure to find out counts as `false`.
    pub(crate) async fn own_identity_matches_list_state(&self) -> bool {
        let result: Result<bool> = async {
            let Some(state) = self.load_own_device_list_state().await? else {
                return Ok(true);
            };
            let current = self
                .get_user_identity(self.user_id())
                .await?
                .and_then(|identity| identity.into_own())
                .as_ref()
                .and_then(self_signing_key_base64);
            Ok(current.as_deref() == Some(state.self_signing_key.as_str()))
        }
        .await;

        result.unwrap_or_else(|error| {
            error!(%error, "Can't read the own-device list state");
            false
        })
    }

    /// Does this device hold the private master and self-signing keys that
    /// match the public ones of `identity`?
    pub(crate) async fn holds_cross_signing_keys_of(&self, identity: &OwnUserIdentityData) -> bool {
        let private = self.private_identity();
        let private = private.lock().await;

        private.has_master_key().await
            && private.can_sign_devices().await
            && private.self_signing_public_key().await.and_then(|k| k.get_first_key())
                == identity.self_signing_key().get_first_key()
            && private.master_public_key().await.and_then(|k| k.get_first_key())
                == identity.master_key().get_first_key()
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

    /// May the account's secrets, and older message keys, be handed to the
    /// device with this ID and Ed25519 key, a device of this user that we
    /// already verified?
    ///
    /// If no valid list has ever been accepted, this is `true` unless the
    /// application has made the list required, in which case it is `false`.
    /// Otherwise it is `true` only if the list in force names the device with
    /// this very key, the last list we were given was valid and not below the
    /// version floor, and it was signed by the self-signing key of our
    /// current, verified identity. Any failure to find out refuses.
    pub(crate) async fn own_device_list_permits(
        &self,
        device_id: &DeviceId,
        ed25519_key: Option<Ed25519PublicKey>,
    ) -> bool {
        match self.own_device_list_permits_inner(device_id, ed25519_key).await {
            Ok(permitted) => permitted,
            Err(error) => {
                error!(%error, "Can't read the own-device list state, not serving the device");
                false
            }
        }
    }

    async fn own_device_list_permits_inner(
        &self,
        device_id: &DeviceId,
        ed25519_key: Option<Ed25519PublicKey>,
    ) -> Result<bool> {
        let Some(state) = self.load_own_device_list_state().await? else {
            return Ok(!self.own_device_list_required().await?);
        };

        // The ID alone proves nothing: a new device can be given the ID of a
        // deleted one. The key has to match what the signed list says.
        let Some(ed25519_key) = ed25519_key else {
            return Ok(false);
        };

        if !state.serving
            || state.devices.get(device_id) != Some(&ed25519_key)
            || state.version < self.own_device_list_version_floor().await?
        {
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
        let floor = self.own_device_list_version_floor().await?;
        let evaluation = self.evaluate_own_device_list(current.as_ref(), candidate).await?;
        let required = self.own_device_list_required().await?;
        let candidate_key = match &evaluation {
            Evaluation::Valid { self_signing_key, .. } => Some(self_signing_key.clone()),
            _ => None,
        };

        let (outcome, new_state) = match (evaluation, candidate) {
            (Evaluation::Valid { self_signing_key, anchored }, Some(list)) => Self::decide(
                current.as_ref(),
                floor,
                self_signing_key,
                anchored,
                (&self.static_account().device_id, self.static_account().identity_keys().ed25519),
                list,
            ),
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

        // A device that did not serve (and so dropped the answers it was sent)
        // and now does: ask for the secrets again, because the answers that
        // came before the list are gone and the requests are marked as sent.
        // To-device events of a sync are processed before the application
        // passes this device the list from the same sync, so this is the usual
        // order for a device that was just approved.
        //
        // This runs before the state is stored: if it fails, the state still
        // says "not serving" and the next list tries again, instead of a
        // serving state with nothing asked for.
        if let (Some(new_state), Some(key)) = (&new_state, &candidate_key) {
            let served_before = match &current {
                Some(state) => state.serving && &state.self_signing_key == key,
                None => !required,
            };
            if new_state.serving && &new_state.self_signing_key == key && !served_before {
                self.requeue_secret_requests().await?;
            }
        }

        if let Some(new_state) = &new_state
            && current.as_ref() != Some(new_state)
        {
            self.store_own_device_list_state(new_state).await?;
        }

        Ok(outcome)
    }

    /// Ask again for the secrets that were requested and not answered, under
    /// new request ids.
    ///
    /// The request id is also the transaction id of the `sendToDevice` call,
    /// and a homeserver answers a repeated transaction id from its cache for
    /// a while without delivering the event again. So the stored request is
    /// replaced by a new one (the same secret, a fresh id) instead of being
    /// marked as unsent. A late answer to the old id finds no request and is
    /// dropped.
    ///
    /// This re-asks for exactly what was asked before, which is what is still
    /// missing: a request is deleted when its secret is answered. The new
    /// request is saved before the old one is deleted, so a failure in between
    /// leaves two requests rather than none.
    ///
    /// Room key requests are not touched: the store can not list them. A new
    /// decryption failure does not ask again while a request for that session
    /// exists, so a forwarded key that was dropped stays missing (where
    /// forwarding is enabled) until the request is cleared.
    async fn requeue_secret_requests(&self) -> Result<()> {
        // A restricted device asks for nothing.
        if self.is_device_restricted().await? {
            return Ok(());
        }

        let mut replaced = Vec::new();
        let mut changes = crate::store::types::Changes::default();
        for name in crate::machine::KNOWN_SECRET_NAMES {
            let info = crate::SecretInfo::SecretRequest(name.clone());
            if let Some(request) = self.get_secret_request_by_info(&info).await?
                && request.sent_out
            {
                debug!(?info, "Asking for a secret again, the own-device list now names us");
                changes.key_requests.push(crate::gossiping::GossipRequest::from_secret_name(
                    request.request_recipient.clone(),
                    name,
                ));
                replaced.push(request.request_id);
            }
        }

        if !changes.key_requests.is_empty() {
            self.save_changes(changes).await?;
        }
        for old_id in replaced {
            self.delete_outgoing_secret_requests(&old_id).await?;
        }

        Ok(())
    }

    /// Decide what a candidate that verified does to the remembered state.
    ///
    /// Returns the outcome, and the state to keep if the candidate was
    /// usable. `None` means the candidate was refused.
    fn decide(
        current: Option<&StoredState>,
        floor: u64,
        self_signing_key: String,
        anchored: bool,
        own_device: (&DeviceId, Ed25519PublicKey),
        list: &OwnDeviceList,
    ) -> (OwnDeviceListOutcome, Option<StoredState>) {
        if current.is_some_and(StoredState::is_unreadable_sentinel) {
            return (OwnDeviceListOutcome::StateUnreadable, None);
        }

        let (outcome, state) =
            Self::decide_version(current, floor, self_signing_key, anchored, list);

        // A list that does not name this device, with this device's key, means
        // it was removed (or that the list predates it). The version is
        // remembered so the list can not be replayed, but nothing is served.
        match (outcome, state) {
            (OwnDeviceListOutcome::Accepted { .. }, Some(state))
                if !list.contains(own_device.0, &own_device.1) =>
            {
                warn!("The own-device list does not name this device, no longer serving");
                (
                    OwnDeviceListOutcome::ThisDeviceNotListed,
                    Some(StoredState { serving: false, ..state }),
                )
            }
            other => other,
        }
    }

    fn decide_version(
        current: Option<&StoredState>,
        floor: u64,
        self_signing_key: String,
        anchored: bool,
        list: &OwnDeviceList,
    ) -> (OwnDeviceListOutcome, Option<StoredState>) {
        let accepted = OwnDeviceListOutcome::Accepted { version: list.version() };
        let fresh = |devices: BTreeMap<OwnedDeviceId, Ed25519PublicKey>| StoredState {
            self_signing_key: self_signing_key.clone(),
            version: list.version(),
            devices,
            serving: true,
        };

        // The version a list has to reach: the floor the application set, and
        // the highest version seen under this same self-signing key.
        let seen_under_this_key = current
            .filter(|state| state.self_signing_key == self_signing_key)
            .map_or(0, |state| state.version);
        let required = floor.max(seen_under_this_key);

        if list.version() < required {
            return (OwnDeviceListOutcome::Rewound { seen: required, got: list.version() }, None);
        }

        match current {
            // The first valid list, at or above the floor: enforcement starts
            // here.
            None => (accepted, Some(fresh(list.devices().clone()))),

            // The user's cross-signing identity changed and we verified the new
            // one. A device that made a new identity for itself would otherwise
            // be able to start a list of its own, so the new identity counts
            // only if a device on the last list we accepted signed its master
            // key. Versions then start again under the new key; the old key's
            // lists can not be replayed, they no longer verify.
            Some(state) if state.self_signing_key != self_signing_key => {
                if anchored {
                    (accepted, Some(fresh(list.devices().clone())))
                } else {
                    (OwnDeviceListOutcome::NewIdentityNotAnchored, None)
                }
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
                let devices = state
                    .devices
                    .iter()
                    .filter(|(id, key)| list.devices().get(*id) == Some(*key))
                    .map(|(id, key)| (id.clone(), *key))
                    .collect();
                (accepted, Some(fresh(devices)))
            }

            // Older than one we accepted: a rewind.
            Some(state) => {
                (OwnDeviceListOutcome::Rewound { seen: state.version, got: list.version() }, None)
            }
        }
    }

    /// Does our own identity's master key carry a valid signature from one of
    /// the devices in `state`, checked against the key the list bound to that
    /// device?
    fn master_key_signed_by_listed_device(
        identity: &OwnUserIdentityData,
        state: &StoredState,
    ) -> bool {
        let master_key: &CrossSigningKey = identity.master_key().as_ref();

        state.devices.iter().any(|(device_id, key)| {
            key.verify_json(
                identity.user_id(),
                &DeviceKeyId::from_parts(DeviceKeyAlgorithm::Ed25519, device_id),
                master_key,
            )
            .is_ok()
        })
    }

    /// Forget the remembered list, so the next valid list starts a new one.
    /// Used when the application adopts a new cross-signing identity.
    pub(crate) async fn forget_own_device_list_state(&self) -> Result<()> {
        let _guard = self.own_device_list_lock().lock().await;
        self.remove_custom_value(OWN_DEVICE_LIST_STATE_KEY).await?;
        Ok(())
    }

    async fn evaluate_own_device_list(
        &self,
        current: Option<&StoredState>,
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
                    let anchored = match current {
                        Some(state) if state.self_signing_key != self_signing_key => {
                            Self::master_key_signed_by_listed_device(&own_identity, state)
                        }
                        _ => true,
                    };
                    Ok(Evaluation::Valid { self_signing_key, anchored })
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
    use std::{
        collections::BTreeMap,
        sync::{Arc, LazyLock},
    };

    use assert_matches2::assert_matches;
    use matrix_sdk_test::async_test;
    use ruma::{DeviceId, OwnedDeviceId, device_id, events::secret::request::SecretName, user_id};
    use serde_json::json;
    use vodozemac::Ed25519PublicKey;

    use super::{OWN_DEVICE_LIST_FLOOR_KEY, OWN_DEVICE_LIST_STATE_KEY, OwnDeviceListOutcome};
    use crate::{
        DeviceData, LocalTrust, OlmMachine, OlmMachineBuilder,
        olm::PrivateCrossSigningIdentity,
        store::MemoryStore,
        types::{
            DeviceKeys, OwnDeviceList, OwnDeviceListError, own_device_list::tests::key as fake_key,
        },
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

    /// Real device keys for `B()` and `C()`, made once per process: a list can
    /// only be signed for devices the signer knows, with their stored keys.
    static OTHER_DEVICES: LazyLock<(DeviceKeys, DeviceKeys)> = LazyLock::new(|| {
        let user = user_id!("@alice:example.org");
        (
            crate::Account::with_device_id(user, B()).device_keys(),
            crate::Account::with_device_id(user, C()).device_keys(),
        )
    });

    /// The key a test device has: the machine's own key for `A()`, which the
    /// machine really signs with, the real keys of `B()` and `C()`, and a
    /// made-up one for anything else.
    fn key_of(machine: &OlmMachine, id: &DeviceId) -> Ed25519PublicKey {
        if id == A() {
            machine.identity_keys().ed25519
        } else if id == B() {
            DeviceData::try_from(&OTHER_DEVICES.0).unwrap().ed25519_key().unwrap()
        } else if id == C() {
            DeviceData::try_from(&OTHER_DEVICES.1).unwrap().ed25519_key().unwrap()
        } else {
            fake_key(id.as_str())
        }
    }

    fn set(machine: &OlmMachine, ids: &[&DeviceId]) -> BTreeMap<OwnedDeviceId, Ed25519PublicKey> {
        ids.iter().map(|id| ((*id).to_owned(), key_of(machine, id))).collect()
    }

    /// Sign a list with the machine's keys *without* accepting it, as another
    /// own device would.
    async fn sign_only(
        machine: &OlmMachine,
        version: u64,
        devices: BTreeMap<OwnedDeviceId, Ed25519PublicKey>,
    ) -> OwnDeviceList {
        let mut list = OwnDeviceList::new(machine.user_id().to_owned(), version, devices);
        machine
            .store()
            .private_identity()
            .lock()
            .await
            .sign_own_device_list(&mut list)
            .await
            .unwrap();
        list
    }

    /// An own device that holds the account's secrets and has verified its own
    /// identity.
    async fn own_machine() -> OlmMachine {
        let machine = OlmMachine::new(user_id!("@alice:example.org"), A()).await;
        machine.bootstrap_cross_signing(false).await.unwrap();
        add_verified_devices(&machine).await;
        machine
    }

    /// Make `B()` and `C()` known, verified devices of the machine.
    async fn add_verified_devices(machine: &OlmMachine) {
        for keys in [&OTHER_DEVICES.0, &OTHER_DEVICES.1] {
            let device = DeviceData::try_from(keys).unwrap();
            device.set_trust_state(LocalTrust::Verified);
            machine.store().save_device_data(&[device]).await.unwrap();
        }
    }

    async fn permits(machine: &OlmMachine, device: &DeviceId) -> bool {
        machine.store().own_device_list_permits(device, Some(key_of(machine, device))).await
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
        let mut forged = OwnDeviceList::new(machine.user_id().to_owned(), 1, set(&machine, &[C()]));
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
        let list = machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();

        assert_eq!(
            machine.receive_own_device_list(Some(&list)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 1 }
        );

        let status = machine.own_device_list_status().await.unwrap().unwrap();
        assert_eq!(
            (status.version, status.devices, status.serving),
            (1, set(&machine, &[A(), B()]), true)
        );
        assert!(permits(&machine, A()).await);
        assert!(permits(&machine, B()).await);
        assert!(!permits(&machine, C()).await);
    }

    #[async_test]
    async fn test_a_deleted_list_stops_serving_until_it_reappears() {
        let machine = own_machine().await;
        let list = machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();
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
        let v1 = machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();
        machine.receive_own_device_list(Some(&v1)).await.unwrap();
        let v2 = machine.sign_own_device_list(2, set(&machine, &[A()])).await.unwrap();
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
        let list = machine.sign_own_device_list(1, set(&machine, &[A()])).await.unwrap();
        machine.receive_own_device_list(Some(&list)).await.unwrap();
        assert!(permits(&machine, A()).await);

        // Altered after signing: a device added and the version raised.
        let mut json = serde_json::to_value(&list).unwrap();
        json["devices"] = json!({
            "DEVICEA": key_of(&machine, A()).to_base64(),
            "DEVICEC": key_of(&machine, C()).to_base64(),
        });
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
        let mut wrong =
            OwnDeviceList::new(machine.user_id().to_owned(), 5, set(&machine, &[A(), C()]));
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
        let list = sign_only(&machine, 1, set(&machine, &[A(), B()])).await;

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
        let old = machine.sign_own_device_list(5, set(&machine, &[A(), B()])).await.unwrap();
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
        let fresh = machine.sign_own_device_list(1, set(&machine, &[A()])).await.unwrap();
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
        let base = machine.sign_own_device_list(1, set(&machine, &[A()])).await.unwrap();
        machine.receive_own_device_list(Some(&base)).await.unwrap();
        let with_b = machine.sign_own_device_list(2, set(&machine, &[A(), B()])).await.unwrap();
        let with_c = {
            // Signed at the same version by "the other device".
            let mut list =
                OwnDeviceList::new(machine.user_id().to_owned(), 2, set(&machine, &[A(), C()]));
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
        let merged =
            machine.sign_own_device_list(3, set(&machine, &[A(), B(), C()])).await.unwrap();
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
        add_verified_devices(&machine).await;
        let v1 = machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();
        machine.receive_own_device_list(Some(&v1)).await.unwrap();
        let v2 = machine.sign_own_device_list(2, set(&machine, &[A()])).await.unwrap();
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

        // Nothing from the unknown history can be trusted to anchor a list,
        // so a list does not repair it by itself...
        let list = sign_only(&machine, 1, set(&machine, &[A(), B()])).await;
        assert_eq!(
            machine.receive_own_device_list(Some(&list)).await.unwrap(),
            OwnDeviceListOutcome::StateUnreadable
        );
        assert!(!permits(&machine, B()).await);

        // ...but the device that holds the account's secrets can start over.
        machine.adopt_own_identity_for_device_list().await.unwrap();
        assert_eq!(
            machine.receive_own_device_list(Some(&list)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 1 }
        );
        assert!(permits(&machine, B()).await);
    }

    #[async_test]
    async fn test_concurrent_updates_never_lower_the_remembered_version() {
        let machine = own_machine().await;
        let v1 = machine.sign_own_device_list(1, set(&machine, &[A()])).await.unwrap();
        let v2 = machine.sign_own_device_list(2, set(&machine, &[A(), B()])).await.unwrap();

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
        let list = machine.sign_own_device_list(4, set(&machine, &[A()])).await.unwrap();
        machine.receive_own_device_list(Some(&list)).await.unwrap();

        for version in [1, 4] {
            assert_matches!(
                machine.sign_own_device_list(version, set(&machine, &[A()])).await,
                Err(OwnDeviceListError::VersionNotAboveSeen { seen: 4, requested })
            );
            assert_eq!(requested, version);
        }
        machine.sign_own_device_list(5, set(&machine, &[A()])).await.unwrap();
    }

    #[async_test]
    async fn test_a_new_device_reusing_a_listed_id_is_refused() {
        let machine = own_machine().await;
        let list = machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();
        machine.receive_own_device_list(Some(&list)).await.unwrap();

        // The listed device B is deleted, and a new device takes its ID with
        // its own, different key. The signed list says nothing of that key.
        let other_key = fake_key("A DIFFERENT DEVICE");
        assert!(permits(&machine, B()).await);
        assert!(!machine.store().own_device_list_permits(B(), Some(other_key)).await);

        // Without a key to compare, nothing is served either.
        assert!(!machine.store().own_device_list_permits(B(), None).await);
    }

    #[async_test]
    async fn test_a_required_list_serves_nobody_until_one_is_accepted() {
        let machine = own_machine().await;
        machine.set_own_device_list_required(true).await.unwrap();
        assert!(machine.own_device_list_required().await.unwrap());

        // A device that never saw a list refuses, whether or not the server
        // shows it one.
        assert!(!permits(&machine, B()).await);
        machine.receive_own_device_list(None).await.unwrap();
        assert!(!permits(&machine, B()).await);

        // The first valid list, from another own device, turns serving on.
        let list = sign_only(&machine, 1, set(&machine, &[A(), B()])).await;
        machine.receive_own_device_list(Some(&list)).await.unwrap();
        assert!(permits(&machine, B()).await);
        assert!(!permits(&machine, C()).await);

        // The mode is persisted and can be lifted.
        machine.set_own_device_list_required(false).await.unwrap();
        assert!(!machine.own_device_list_required().await.unwrap());
    }

    #[async_test]
    async fn test_the_signer_enforces_its_own_list_with_no_server_echo() {
        let machine = own_machine().await;
        machine.set_own_device_list_required(true).await.unwrap();

        // The signer never has the list handed back to it.
        machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();

        let status = machine.own_device_list_status().await.unwrap().unwrap();
        assert_eq!((status.version, status.serving), (1, true));
        assert!(permits(&machine, B()).await);
        assert!(!permits(&machine, C()).await);

        // Without the mode, signing a list starts enforcement all the same.
        let machine = own_machine().await;
        assert!(permits(&machine, C()).await);
        machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();
        assert!(!permits(&machine, C()).await);
    }

    #[async_test]
    async fn test_the_version_floor_rejects_a_lower_first_list() {
        let machine = own_machine().await;
        machine.set_own_device_list_version_floor(5).await.unwrap();
        assert_eq!(machine.own_device_list_version_floor().await.unwrap(), 5);

        // A fresh device handed an old, genuinely signed list by the server.
        let old = sign_only(&machine, 3, set(&machine, &[A(), B(), C()])).await;
        assert_eq!(
            machine.receive_own_device_list(Some(&old)).await.unwrap(),
            OwnDeviceListOutcome::Rewound { seen: 5, got: 3 }
        );
        assert_eq!(machine.own_device_list_status().await.unwrap(), None);

        // At the floor it is accepted.
        let at_floor = sign_only(&machine, 5, set(&machine, &[A(), B()])).await;
        assert_eq!(
            machine.receive_own_device_list(Some(&at_floor)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 5 }
        );
        assert!(permits(&machine, B()).await);
        assert!(!permits(&machine, C()).await);
    }

    #[async_test]
    async fn test_raising_the_floor_stops_serving_from_a_lower_list() {
        let machine = own_machine().await;
        machine.sign_own_device_list(2, set(&machine, &[A(), B()])).await.unwrap();
        assert!(permits(&machine, B()).await);

        machine.set_own_device_list_version_floor(3).await.unwrap();
        assert!(!permits(&machine, B()).await);

        let v3 = sign_only(&machine, 3, set(&machine, &[A(), B()])).await;
        machine.receive_own_device_list(Some(&v3)).await.unwrap();
        assert!(permits(&machine, B()).await);
    }

    #[async_test]
    async fn test_a_floor_written_by_another_process_is_honoured_at_serving_time() {
        let machine = own_machine().await;
        machine.sign_own_device_list(2, set(&machine, &[A(), B()])).await.unwrap();
        assert!(permits(&machine, B()).await);

        // Another process of the same app raised the floor; this one has not
        // run `set_own_device_list_version_floor`, so its stored state still
        // says it is serving.
        machine
            .store()
            .set_custom_value(OWN_DEVICE_LIST_FLOOR_KEY, rmp_serde::to_vec(&7u64).unwrap())
            .await
            .unwrap();
        assert!(machine.own_device_list_status().await.unwrap().unwrap().serving);

        assert!(!permits(&machine, B()).await);
    }

    #[async_test]
    async fn test_an_unreadable_floor_refuses() {
        let machine = own_machine().await;
        machine.set_own_device_list_required(true).await.unwrap();
        machine
            .store()
            .set_custom_value(OWN_DEVICE_LIST_FLOOR_KEY, b"\xc1".to_vec())
            .await
            .unwrap();

        assert_eq!(machine.own_device_list_version_floor().await.unwrap(), u64::MAX);
        let list = sign_only(&machine, 7, set(&machine, &[A(), B()])).await;
        assert_matches!(
            machine.receive_own_device_list(Some(&list)).await.unwrap(),
            OwnDeviceListOutcome::Rewound { .. }
        );
        assert!(!permits(&machine, B()).await);
    }

    /// Give `machine` the public identity of `other` as its own, verified, as
    /// when the user's cross-signing identity was replaced.
    async fn replace_public_identity(machine: &OlmMachine, other: &OlmMachine) {
        let identity = other
            .store()
            .get_user_identity(other.user_id())
            .await
            .unwrap()
            .unwrap()
            .into_own()
            .unwrap();
        identity.mark_as_verified();
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
    }

    #[async_test]
    async fn test_a_borrowed_device_made_identity_is_not_trusted() {
        let machine = own_machine().await;
        machine.set_own_device_list_required(true).await.unwrap();
        let list = machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();
        assert!(permits(&machine, B()).await);

        // A borrowed device makes a new identity for the account, signs its
        // own master key with itself, and lists itself.
        let borrowed =
            OlmMachine::new(user_id!("@alice:example.org"), device_id!("BORROWED")).await;
        borrowed.bootstrap_cross_signing(false).await.unwrap();
        let hers = borrowed
            .sign_own_device_list(
                1,
                BTreeMap::from([(
                    device_id!("BORROWED").to_owned(),
                    borrowed.identity_keys().ed25519,
                )]),
            )
            .await
            .unwrap();

        // The server swaps the identity and the list, and the user, shown the
        // new identity, marked it verified.
        replace_public_identity(&machine, &borrowed).await;

        assert_eq!(
            machine.receive_own_device_list(Some(&hers)).await.unwrap(),
            OwnDeviceListOutcome::NewIdentityNotAnchored
        );
        assert!(!permits(&machine, B()).await);
        assert!(
            !machine
                .store()
                .own_device_list_permits(
                    device_id!("BORROWED"),
                    Some(borrowed.identity_keys().ed25519)
                )
                .await
        );

        // Replaying the old identity's list changes nothing: it does not
        // verify under the new key.
        assert_eq!(
            machine.receive_own_device_list(Some(&list)).await.unwrap(),
            OwnDeviceListOutcome::Invalid
        );
        assert!(!permits(&machine, B()).await);
        assert!(!permits(&machine, A()).await);
        assert_eq!(machine.own_device_list_status().await.unwrap().unwrap().version, 1);
    }

    #[async_test]
    async fn test_a_new_identity_signed_by_a_listed_device_is_accepted() {
        let machine = own_machine().await;
        machine.sign_own_device_list(4, set(&machine, &[A(), B()])).await.unwrap();

        // A listed device (here A itself) resets cross-signing: the new
        // master key carries its signature.
        machine.bootstrap_cross_signing(true).await.unwrap();

        // The old list is no use any more.
        assert!(!permits(&machine, B()).await);

        let fresh = machine.sign_own_device_list(1, set(&machine, &[A(), C()])).await.unwrap();
        assert_eq!(
            machine.receive_own_device_list(Some(&fresh)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 1 }
        );
        assert!(permits(&machine, C()).await);
        assert!(!permits(&machine, B()).await);
    }

    #[async_test]
    async fn test_a_listed_device_signature_is_checked_against_the_listed_key() {
        let machine = own_machine().await;
        // The list names A with a key that is not the one A signs with.
        let mut devices = set(&machine, &[A(), B()]);
        devices.insert(A().to_owned(), fake_key("NOT A'S KEY"));
        // (Another own device signed it; this device would refuse to.)
        let list = sign_only(&machine, 1, devices).await;
        machine.receive_own_device_list(Some(&list)).await.unwrap();

        // The new master key is signed by A's real key, which the list does
        // not bind to A, so the identity is not anchored.
        let other = OlmMachine::new(user_id!("@alice:example.org"), A()).await;
        other.bootstrap_cross_signing(false).await.unwrap();
        let hers = other
            .sign_own_device_list(
                1,
                BTreeMap::from([(A().to_owned(), other.identity_keys().ed25519)]),
            )
            .await
            .unwrap();
        replace_public_identity(&machine, &other).await;

        assert_eq!(
            machine.receive_own_device_list(Some(&hers)).await.unwrap(),
            OwnDeviceListOutcome::NewIdentityNotAnchored
        );
    }

    #[async_test]
    async fn test_adopting_a_new_identity_needs_its_secrets() {
        let machine = own_machine().await;
        machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();

        // A genuine "start fresh" happened on a device that is not on the
        // list. This device sees the new public identity and verifies it.
        let fresh = OlmMachine::new(user_id!("@alice:example.org"), device_id!("FRESH")).await;
        fresh.bootstrap_cross_signing(false).await.unwrap();
        let fresh_list = fresh
            .sign_own_device_list(
                1,
                BTreeMap::from([(device_id!("FRESH").to_owned(), fresh.identity_keys().ed25519)]),
            )
            .await
            .unwrap();
        // The list that names this device as well, as the app would sign it
        // once it knows this device.
        let mut fresh_list_with_this_device = OwnDeviceList::new(
            machine.user_id().to_owned(),
            2,
            BTreeMap::from([
                (device_id!("FRESH").to_owned(), fresh.identity_keys().ed25519),
                (A().to_owned(), machine.identity_keys().ed25519),
            ]),
        );
        fresh
            .store()
            .private_identity()
            .lock()
            .await
            .sign_own_device_list(&mut fresh_list_with_this_device)
            .await
            .unwrap();
        replace_public_identity(&machine, &fresh).await;

        assert_eq!(
            machine.receive_own_device_list(Some(&fresh_list)).await.unwrap(),
            OwnDeviceListOutcome::NewIdentityNotAnchored
        );

        // It does not hold the private keys, so it can not adopt.
        assert_matches!(
            machine.adopt_own_identity_for_device_list().await,
            Err(OwnDeviceListError::SecretsNotHeld)
        );

        // After the recovery key (the secrets bundle) is imported it can.
        let bundle = fresh.store().export_secrets_bundle().await.unwrap();
        machine.store().import_secrets_bundle(&bundle).await.unwrap();
        machine.adopt_own_identity_for_device_list().await.unwrap();
        assert_eq!(machine.own_device_list_status().await.unwrap(), None);

        // A list that does not name this device is still not accepted...
        assert_eq!(
            machine.receive_own_device_list(Some(&fresh_list)).await.unwrap(),
            OwnDeviceListOutcome::ThisDeviceNotListed
        );
        assert!(!permits(&machine, A()).await);

        // ...one that does is.
        assert_eq!(
            machine.receive_own_device_list(Some(&fresh_list_with_this_device)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 2 }
        );
    }

    #[async_test]
    async fn test_a_restricted_device_can_not_adopt_an_identity() {
        let machine = own_machine().await;
        machine.set_device_restricted(true).await.unwrap();

        assert_matches!(
            machine.adopt_own_identity_for_device_list().await,
            Err(OwnDeviceListError::Restricted)
        );
    }

    #[async_test]
    async fn test_a_list_that_leaves_this_device_out_serves_nobody() {
        let machine = own_machine().await;
        machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();
        assert!(permits(&machine, B()).await);

        // Another own device removes this one in version 2.
        let removed = sign_only(&machine, 2, set(&machine, &[B(), C()])).await;
        assert_eq!(
            machine.receive_own_device_list(Some(&removed)).await.unwrap(),
            OwnDeviceListOutcome::ThisDeviceNotListed
        );
        assert!(!permits(&machine, B()).await);
        assert!(!permits(&machine, C()).await);
        let status = machine.own_device_list_status().await.unwrap().unwrap();
        assert_eq!((status.version, status.serving), (2, false));

        // The old list that still names this device can not bring it back.
        let old = sign_only(&machine, 1, set(&machine, &[A(), B()])).await;
        assert_eq!(
            machine.receive_own_device_list(Some(&old)).await.unwrap(),
            OwnDeviceListOutcome::Rewound { seen: 2, got: 1 }
        );
        assert!(!permits(&machine, B()).await);
    }

    #[async_test]
    async fn test_a_new_device_does_not_accept_a_list_from_before_it_existed() {
        let machine = own_machine().await;

        // A genuine, correctly signed old list, with the floor never set. It
        // can not name this device's key, so even the first accept is pinned.
        let old = sign_only(&machine, 1, fake_devices_with(&[B(), C()])).await;
        machine.set_own_device_list_required(true).await.unwrap();
        assert_eq!(
            machine.receive_own_device_list(Some(&old)).await.unwrap(),
            OwnDeviceListOutcome::ThisDeviceNotListed
        );
        assert!(!permits(&machine, B()).await);
    }

    fn fake_devices_with(ids: &[&DeviceId]) -> BTreeMap<OwnedDeviceId, Ed25519PublicKey> {
        ids.iter().map(|id| ((*id).to_owned(), fake_key(id.as_str()))).collect()
    }

    #[async_test]
    async fn test_a_signer_must_name_itself() {
        let machine = own_machine().await;

        assert_matches!(
            machine.sign_own_device_list(1, set(&machine, &[B(), C()])).await,
            Err(OwnDeviceListError::NotAccepted(OwnDeviceListOutcome::ThisDeviceNotListed))
        );
        assert_eq!(machine.own_device_list_status().await.unwrap(), None);
    }

    #[async_test]
    async fn test_the_signer_only_lists_known_verified_devices_with_their_stored_keys() {
        let machine = own_machine().await;

        // Unknown device.
        let mut devices = set(&machine, &[A()]);
        devices.insert(device_id!("UNKNOWN").to_owned(), fake_key("UNKNOWN"));
        assert_matches!(
            machine.sign_own_device_list(1, devices).await,
            Err(OwnDeviceListError::InvalidDevice(_, "unknown device"))
        );

        // A known device with a key the store does not have for it.
        let mut devices = set(&machine, &[A(), B()]);
        devices.insert(B().to_owned(), fake_key("SERVER SUPPLIED"));
        assert_matches!(
            machine.sign_own_device_list(1, devices).await,
            Err(OwnDeviceListError::InvalidDevice(_, "the key differs from the stored key"))
        );

        // This device with a key that is not its own.
        let mut devices = set(&machine, &[A()]);
        devices.insert(A().to_owned(), fake_key("NOT MINE"));
        assert_matches!(
            machine.sign_own_device_list(1, devices).await,
            Err(OwnDeviceListError::InvalidDevice(_, "not this device's key"))
        );

        // A known device that is not verified.
        let unverified =
            OlmMachine::new(user_id!("@alice:example.org"), device_id!("UNVERIFIED")).await;
        let device = DeviceData::try_from(
            &unverified.store().cache().await.unwrap().account().await.unwrap().device_keys(),
        )
        .unwrap();
        machine.store().save_device_data(&[device]).await.unwrap();
        let mut devices = set(&machine, &[A()]);
        devices.insert(device_id!("UNVERIFIED").to_owned(), unverified.identity_keys().ed25519);
        assert_matches!(
            machine.sign_own_device_list(1, devices).await,
            Err(OwnDeviceListError::InvalidDevice(_, "not verified"))
        );

        assert_eq!(machine.own_device_list_status().await.unwrap(), None);
    }

    #[async_test]
    async fn test_the_version_floor_only_goes_up() {
        let machine = own_machine().await;

        machine.set_own_device_list_version_floor(5).await.unwrap();
        machine.set_own_device_list_version_floor(3).await.unwrap();
        assert_eq!(machine.own_device_list_version_floor().await.unwrap(), 5);
        machine.set_own_device_list_version_floor(9).await.unwrap();
        assert_eq!(machine.own_device_list_version_floor().await.unwrap(), 9);

        // Only an unreadable floor may be replaced by a lower one.
        machine
            .store()
            .set_custom_value(OWN_DEVICE_LIST_FLOOR_KEY, b"\xc1".to_vec())
            .await
            .unwrap();
        assert_eq!(machine.own_device_list_version_floor().await.unwrap(), u64::MAX);
        machine.set_own_device_list_version_floor(2).await.unwrap();
        assert_eq!(machine.own_device_list_version_floor().await.unwrap(), 2);
    }

    #[async_test]
    async fn test_verifying_a_replaced_own_identity_needs_its_keys() {
        let machine = own_machine().await;
        machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();

        // A borrowed device replaced the identity.
        let borrowed =
            OlmMachine::new(user_id!("@alice:example.org"), device_id!("BORROWED")).await;
        borrowed.bootstrap_cross_signing(false).await.unwrap();
        replace_public_identity(&machine, &borrowed).await;
        let identity = |m: &OlmMachine| {
            let m = m.clone();
            async move { m.get_identity(m.user_id(), None).await.unwrap().unwrap().own().unwrap() }
        };

        // One tap would sign the new master key with this device's key, which
        // the list would then count as an anchor.
        assert_matches!(
            identity(&machine).await.verify().await,
            Err(crate::SignatureError::UnanchoredIdentity)
        );

        // With the new identity's private keys in hand it is allowed.
        let bundle = borrowed.store().export_secrets_bundle().await.unwrap();
        machine.store().import_secrets_bundle(&bundle).await.unwrap();
        identity(&machine).await.verify().await.unwrap();

        // And with no list at all nothing changes.
        let other = own_machine().await;
        identity(&other).await.verify().await.unwrap();
    }

    /// Store a secret request for the recovery key that was sent out and not
    /// answered.
    async fn sent_recovery_key_request(machine: &OlmMachine) {
        let mut requests = crate::gossiping::GossipMachine::request_missing_secrets(
            machine.user_id(),
            vec![SecretName::RecoveryKey],
        );
        requests[0].sent_out = true;
        let changes = crate::store::types::Changes { key_requests: requests, ..Default::default() };
        machine.store().save_changes(changes).await.unwrap();
    }

    async fn queued_secret_requests(machine: &OlmMachine) -> usize {
        machine.inner.key_request_machine.outgoing_to_device_requests().await.unwrap().len()
    }

    async fn recovery_key_request_id(machine: &OlmMachine) -> ruma::OwnedTransactionId {
        machine
            .store()
            .get_secret_request_by_info(&crate::SecretInfo::SecretRequest(SecretName::RecoveryKey))
            .await
            .unwrap()
            .expect("the request is stored")
            .request_id
    }

    async fn recovery_key_request_is_sent(machine: &OlmMachine) -> bool {
        machine
            .store()
            .get_secret_request_by_info(&crate::SecretInfo::SecretRequest(SecretName::RecoveryKey))
            .await
            .unwrap()
            .expect("the request is stored")
            .sent_out
    }

    #[async_test]
    async fn test_a_device_that_starts_serving_asks_for_its_secrets_again() {
        let machine = own_machine().await;
        machine.set_own_device_list_required(true).await.unwrap();
        sent_recovery_key_request(&machine).await;

        // The answers that came before a list named this device were dropped;
        // the request stays marked as sent.
        let before = sign_only(&machine, 1, set(&machine, &[B(), C()])).await;
        assert_eq!(
            machine.receive_own_device_list(Some(&before)).await.unwrap(),
            OwnDeviceListOutcome::ThisDeviceNotListed
        );
        assert!(recovery_key_request_is_sent(&machine).await);
        assert!(queued_secret_requests(&machine).await == 0);

        // The list that names it: the request goes out again.
        let old_id = recovery_key_request_id(&machine).await;
        let after = sign_only(&machine, 2, set(&machine, &[A(), B()])).await;
        assert_eq!(
            machine.receive_own_device_list(Some(&after)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 2 }
        );
        assert!(!recovery_key_request_is_sent(&machine).await);
        assert_eq!(queued_secret_requests(&machine).await, 1);

        // Under a new id, and the old request is gone.
        assert_ne!(recovery_key_request_id(&machine).await, old_id);
        assert!(machine.store().get_outgoing_secret_requests(&old_id).await.unwrap().is_none());
    }

    #[async_test]
    async fn test_the_first_list_under_enforcement_asks_for_the_secrets_again() {
        // No state at all, but enforcing: nothing was served or accepted.
        let machine = own_machine().await;
        machine.set_own_device_list_required(true).await.unwrap();
        sent_recovery_key_request(&machine).await;

        let list = sign_only(&machine, 1, set(&machine, &[A(), B()])).await;
        machine.receive_own_device_list(Some(&list)).await.unwrap();

        assert!(!recovery_key_request_is_sent(&machine).await);
    }

    #[async_test]
    async fn test_a_device_that_already_serves_does_not_ask_again() {
        let machine = own_machine().await;
        machine.sign_own_device_list(1, set(&machine, &[A(), B()])).await.unwrap();
        sent_recovery_key_request(&machine).await;

        // serving -> serving
        let next = sign_only(&machine, 2, set(&machine, &[A(), B(), C()])).await;
        assert_eq!(
            machine.receive_own_device_list(Some(&next)).await.unwrap(),
            OwnDeviceListOutcome::Accepted { version: 2 }
        );
        assert!(recovery_key_request_is_sent(&machine).await);
    }

    #[async_test]
    async fn test_the_first_list_without_enforcement_does_not_ask_again() {
        // Not enforcing and no state: the device took every answer already.
        let machine = own_machine().await;
        sent_recovery_key_request(&machine).await;

        let list = sign_only(&machine, 1, set(&machine, &[A(), B()])).await;
        machine.receive_own_device_list(Some(&list)).await.unwrap();

        assert!(recovery_key_request_is_sent(&machine).await);
    }

    #[async_test]
    async fn test_an_answered_request_is_not_asked_again() {
        let machine = own_machine().await;
        machine.set_own_device_list_required(true).await.unwrap();

        // An answered request is deleted, so there is nothing to send again.
        let list = sign_only(&machine, 1, set(&machine, &[A(), B()])).await;
        machine.receive_own_device_list(Some(&list)).await.unwrap();

        assert!(queued_secret_requests(&machine).await == 0);
    }

    #[async_test]
    async fn test_a_restricted_device_does_not_ask_for_secrets_again() {
        let machine = own_machine().await;
        machine.set_own_device_list_required(true).await.unwrap();
        machine.set_device_restricted(true).await.unwrap();
        // A request that got stored after the flag was set, say in a race.
        sent_recovery_key_request(&machine).await;

        let list = sign_only(&machine, 1, set(&machine, &[A(), B()])).await;
        machine.receive_own_device_list(Some(&list)).await.unwrap();

        assert!(recovery_key_request_is_sent(&machine).await);
    }
}
