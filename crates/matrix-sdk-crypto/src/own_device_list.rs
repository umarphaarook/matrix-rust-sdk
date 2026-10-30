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

use std::collections::BTreeSet;

use ruma::{DeviceId, OwnedDeviceId};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    store::{CryptoStoreError, Result, Store},
    types::{OwnDeviceList, OwnDeviceListError},
};

/// The custom-value key under which the remembered list state is stored.
const OWN_DEVICE_LIST_STATE_KEY: &str = "zaure.own_device_list_state";

/// What this device remembers about the own-device list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredState {
    /// The devices on the most recent valid list this device has accepted.
    devices: BTreeSet<OwnedDeviceId>,

    /// Whether the list this device was last given was valid. While `false`
    /// nobody is served.
    serving: bool,
}

/// The own-device list a device is serving from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnDeviceListStatus {
    /// The devices that may be served.
    pub devices: BTreeSet<OwnedDeviceId>,

    /// Whether this device is serving at all right now. It is not when the
    /// list it was last given was missing or invalid.
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

    /// This device has no verified own identity to check a list against.
    NoTrustedIdentity,
}

impl Store {
    async fn load_own_device_list_state(&self) -> Result<Option<StoredState>> {
        self.get_value(OWN_DEVICE_LIST_STATE_KEY).await
    }

    async fn store_own_device_list_state(&self, state: &StoredState) -> Result<()> {
        self.set_value(OWN_DEVICE_LIST_STATE_KEY, state).await
    }

    /// The own-device list this device is serving from, if it has accepted
    /// one.
    pub async fn own_device_list_status(&self) -> Result<Option<OwnDeviceListStatus>> {
        Ok(self
            .load_own_device_list_state()
            .await?
            .map(|state| OwnDeviceListStatus { devices: state.devices, serving: state.serving }))
    }

    /// May the account's secrets, and older message keys, be handed to
    /// `device_id`, a device of this user that we already verified?
    ///
    /// `true` if no valid list has ever been accepted (nothing is enforced),
    /// otherwise only if the device is on the list in force. Any failure to
    /// find out refuses.
    pub(crate) async fn own_device_list_permits(&self, device_id: &DeviceId) -> bool {
        match self.load_own_device_list_state().await {
            Ok(None) => true,
            Ok(Some(state)) => state.serving && state.devices.contains(device_id),
            Err(error) => {
                error!(%error, "Can't read the own-device list state, not serving the device");
                false
            }
        }
    }

    /// Process the own-device list as the application last read it.
    pub(crate) async fn receive_own_device_list(
        &self,
        candidate: Option<&OwnDeviceList>,
    ) -> std::result::Result<OwnDeviceListOutcome, CryptoStoreError> {
        let _guard = self.own_device_list_lock().lock().await;

        let outcome = self.evaluate_own_device_list(candidate).await?;

        let current = self.load_own_device_list_state().await?;

        match (&outcome, candidate) {
            (OwnDeviceListOutcome::Accepted { .. }, Some(list)) => {
                let state = StoredState { devices: list.devices().clone(), serving: true };
                if current.as_ref() != Some(&state) {
                    self.store_own_device_list_state(&state).await?;
                }
            }
            // Not valid: once a list has been accepted, stop serving until a
            // valid one is seen again. Before that there is nothing to stop.
            _ => {
                if let Some(mut state) = current
                    && state.serving
                {
                    warn!(?outcome, "The own-device list is not usable, no longer serving");
                    state.serving = false;
                    self.store_own_device_list_state(&state).await?;
                }
            }
        }

        Ok(outcome)
    }

    async fn evaluate_own_device_list(
        &self,
        candidate: Option<&OwnDeviceList>,
    ) -> std::result::Result<OwnDeviceListOutcome, CryptoStoreError> {
        let Some(list) = candidate else {
            return Ok(OwnDeviceListOutcome::Missing);
        };

        // The list is checked against the self-signing key of our own
        // identity, and only if we have verified that identity: the server
        // supplies the identity, so an unverified one proves nothing.
        let own_identity = self
            .get_user_identity(self.user_id())
            .await?
            .and_then(|identity| identity.into_own())
            .filter(|identity| identity.is_verified());

        let Some(own_identity) = own_identity else {
            return Ok(OwnDeviceListOutcome::NoTrustedIdentity);
        };

        match list.verify(own_identity.self_signing_key()) {
            Ok(()) => {
                info!(version = list.version(), "Accepted the own-device list");
                Ok(OwnDeviceListOutcome::Accepted { version: list.version() })
            }
            Err(OwnDeviceListError::Store(error)) => Err(error),
            Err(error) => {
                warn!(%error, "The own-device list is not valid");
                Ok(OwnDeviceListOutcome::Invalid)
            }
        }
    }
}
