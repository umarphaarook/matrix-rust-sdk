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

//! Restricting a borrowed device.
//!
//! A *restricted* device is one the user confirmed but does not own: it must
//! never ask the account's other devices for the signing secrets or the
//! backup key, and must discard any it is sent. The flag lives in the crypto
//! store as a custom value, so it is persisted by every store backend without
//! a schema change, and it is off for every existing account.
//!
//! The flag is opt-in: nothing here changes behaviour until the application
//! calls [`OlmMachine::set_device_restricted`](crate::OlmMachine).

use crate::store::{CryptoStoreError, DynCryptoStore, Result, Store};

/// The custom-value key under which the restricted flag is stored. The flag is
/// set when the key is present, whatever the value.
pub(crate) const RESTRICTED_DEVICE_KEY: &str = "zaure.restricted_device";

/// Read the restricted flag from the raw store.
///
/// Callers that only hold the store wrapper (the verification code) use this;
/// everything else goes through [`Store::is_device_restricted`].
pub(crate) async fn load_restricted_flag(
    store: &DynCryptoStore,
) -> std::result::Result<bool, CryptoStoreError> {
    Ok(store.get_custom_value(RESTRICTED_DEVICE_KEY).await?.is_some())
}

impl Store {
    /// Is this device restricted from receiving the account's secrets?
    pub async fn is_device_restricted(&self) -> Result<bool> {
        load_restricted_flag(&**self).await
    }

    /// Set or clear the restricted flag. It is persisted across restarts.
    ///
    /// This only changes the flag. A device that wants to lift the restriction
    /// because it now holds the secrets (the user entered the recovery key)
    /// calls this with `false` as part of that action.
    pub(crate) async fn store_device_restricted(&self, restricted: bool) -> Result<()> {
        if restricted {
            self.set_custom_value(RESTRICTED_DEVICE_KEY, vec![1]).await?;
        } else {
            self.remove_custom_value(RESTRICTED_DEVICE_KEY).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use matrix_sdk_test::async_test;
    use ruma::{UserId, device_id, user_id};

    use crate::{
        OlmMachineBuilder,
        gossiping::SecretInfo,
        machine::test_helpers::{get_machine_pair, get_machine_pair_with_session},
        store::{DynCryptoStore, MemoryStore},
        types::requests::AnyOutgoingRequest,
    };

    fn alice_id() -> &'static UserId {
        user_id!("@alice:example.org")
    }

    fn bob_id() -> &'static UserId {
        user_id!("@bob:example.org")
    }

    /// Count the unsent `m.secret.request`s in the store.
    async fn unsent_secret_requests(store: &DynCryptoStore) -> usize {
        store
            .get_unsent_secret_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| matches!(r.info, SecretInfo::SecretRequest(_)))
            .count()
    }

    #[async_test]
    async fn test_restricted_flag_defaults_to_off_and_round_trips() {
        let (alice, _, _) = get_machine_pair(alice_id(), bob_id(), false).await;

        assert!(!alice.is_device_restricted().await.unwrap());
        alice.set_device_restricted(true).await.unwrap();
        assert!(alice.is_device_restricted().await.unwrap());
        alice.set_device_restricted(false).await.unwrap();
        assert!(!alice.is_device_restricted().await.unwrap());
    }

    #[async_test]
    async fn test_restricted_flag_survives_a_restart() {
        let store = Arc::new(MemoryStore::new());
        let user = user_id!("@alice:example.org");
        let device = device_id!("RESTARTDEV");

        let machine = OlmMachineBuilder::new(user, device)
            .with_crypto_store(store.clone())
            .build()
            .await
            .unwrap();
        machine.set_device_restricted(true).await.unwrap();
        drop(machine);

        let machine =
            OlmMachineBuilder::new(user, device).with_crypto_store(store).build().await.unwrap();
        assert!(machine.is_device_restricted().await.unwrap());
    }

    #[async_test]
    async fn test_restricted_machine_does_not_query_missing_secrets() {
        let (alice, _) = get_machine_pair_with_session(alice_id(), bob_id(), false).await;

        alice.set_device_restricted(true).await.unwrap();
        assert!(!alice.query_missing_secrets_from_other_sessions().await.unwrap());

        let secret_requests = alice
            .outgoing_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|outgoing| match outgoing.request.as_ref() {
                AnyOutgoingRequest::ToDeviceRequest(request) => {
                    request.event_type.to_string() == "m.secret.request"
                }
                _ => false,
            })
            .count();
        assert_eq!(secret_requests, 0);

        // Lifting the restriction restores the old behaviour.
        alice.set_device_restricted(false).await.unwrap();
        assert!(alice.query_missing_secrets_from_other_sessions().await.unwrap());
    }

    #[async_test]
    async fn test_marking_restricted_drops_queued_secret_requests() {
        let (alice, _) = get_machine_pair_with_session(alice_id(), bob_id(), false).await;

        assert!(alice.query_missing_secrets_from_other_sessions().await.unwrap());
        assert!(unsent_secret_requests(&**alice.store()).await > 0);

        alice.set_device_restricted(true).await.unwrap();
        assert_eq!(unsent_secret_requests(&**alice.store()).await, 0);
    }
}
