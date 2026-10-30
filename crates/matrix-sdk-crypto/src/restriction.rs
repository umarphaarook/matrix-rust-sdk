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
        OlmMachineBuilder, SignatureError,
        gossiping::SecretInfo,
        machine::test_helpers::{get_machine_pair, get_machine_pair_with_session},
        store::{DynCryptoStore, MemoryStore},
        types::{OwnDeviceListError, requests::AnyOutgoingRequest},
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

    /// A user's device that holds the account's secrets, with its identity
    /// saved in its store, and a second device of the same user that knows the
    /// public identity only.
    async fn own_device_and_borrowed_device() -> (crate::OlmMachine, crate::OlmMachine) {
        let user = alice_id();
        let own = crate::OlmMachine::new(user, device_id!("OWNDEVICE")).await;
        let borrowed = crate::OlmMachine::new(user, device_id!("BORROWED")).await;

        own.bootstrap_cross_signing(false).await.unwrap();
        let public = own.store().get_user_identity(user).await.unwrap().unwrap();
        borrowed
            .store()
            .save_changes(crate::store::types::Changes {
                identities: crate::store::types::IdentityChanges {
                    new: vec![public],
                    ..Default::default()
                },
                ..Default::default()
            })
            .await
            .unwrap();

        (own, borrowed)
    }

    /// A list naming just this machine, with its real key.
    fn device_set(
        machine: &crate::OlmMachine,
    ) -> std::collections::BTreeMap<ruma::OwnedDeviceId, vodozemac::Ed25519PublicKey> {
        std::collections::BTreeMap::from([(
            machine.device_id().to_owned(),
            machine.identity_keys().ed25519,
        )])
    }

    #[async_test]
    async fn test_own_device_signs_a_list_that_verifies() {
        let (own, _) = own_device_and_borrowed_device().await;

        let list = own.sign_own_device_list(1, device_set(&own)).await.unwrap();

        let identity =
            own.store().get_user_identity(alice_id()).await.unwrap().unwrap().into_own().unwrap();
        list.verify(identity.self_signing_key()).unwrap();
        assert_eq!(list.version(), 1);
        assert!(list.devices().contains_key(device_id!("OWNDEVICE")));
    }

    #[async_test]
    async fn test_borrowed_device_cannot_sign_a_list() {
        let (_, borrowed) = own_device_and_borrowed_device().await;

        // It does not hold the self-signing key, so it can not sign...
        assert_matches::assert_matches!(
            borrowed.sign_own_device_list(1, device_set(&borrowed)).await,
            Err(OwnDeviceListError::Signature(SignatureError::MissingSigningKey))
        );

        // ...and once marked restricted it refuses outright.
        borrowed.set_device_restricted(true).await.unwrap();
        assert_matches::assert_matches!(
            borrowed.sign_own_device_list(1, device_set(&borrowed)).await,
            Err(OwnDeviceListError::Restricted)
        );
    }

    #[async_test]
    async fn test_restricted_device_cannot_sign_even_with_the_keys() {
        let (own, _) = own_device_and_borrowed_device().await;

        own.set_device_restricted(true).await.unwrap();
        assert_matches::assert_matches!(
            own.sign_own_device_list(1, device_set(&own)).await,
            Err(OwnDeviceListError::Restricted)
        );
    }

    #[async_test]
    async fn test_a_device_without_an_own_identity_cannot_sign_a_list() {
        let machine = crate::OlmMachine::new(alice_id(), device_id!("NOIDENTITY")).await;

        assert_matches::assert_matches!(
            machine.sign_own_device_list(1, device_set(&machine)).await,
            Err(OwnDeviceListError::NoOwnIdentity)
        );
    }

    async fn secret_request_count(machine: &crate::OlmMachine) -> usize {
        machine
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
            .count()
    }

    #[async_test]
    async fn test_restricted_device_does_not_create_a_cross_signing_identity() {
        let machine = crate::OlmMachine::new(alice_id(), device_id!("BORROWED")).await;
        machine.set_device_restricted(true).await.unwrap();

        // Neither the first bootstrap nor a reset.
        for reset in [false, true] {
            assert!(matches!(
                machine.bootstrap_cross_signing(reset).await,
                Err(crate::BootstrapCrossSigningError::Signature(SignatureError::DeviceRestricted))
            ));
        }
        assert!(machine.store().get_user_identity(alice_id()).await.unwrap().is_none());
        assert!(!machine.cross_signing_status().await.has_self_signing);

        // Control: lifting the restriction restores the old behaviour.
        machine.set_device_restricted(false).await.unwrap();
        machine.bootstrap_cross_signing(false).await.unwrap();
        assert!(machine.cross_signing_status().await.has_self_signing);
    }

    #[async_test]
    async fn test_marking_restricted_purges_a_recovery_key_from_the_secret_inbox() {
        use ruma::events::secret::request::SecretName;

        use crate::store::types::{Changes, SecretsInboxItem};

        let machine = crate::OlmMachine::new(alice_id(), device_id!("BORROWED")).await;
        machine
            .store()
            .save_changes(Changes {
                secrets: vec![SecretsInboxItem {
                    secret_name: SecretName::RecoveryKey,
                    secret: "a recovery key that arrived early".to_owned().into(),
                }],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            machine.store().get_secrets_from_inbox(&SecretName::RecoveryKey).await.unwrap().len(),
            1
        );

        // Control: lifting a restriction that was never set purges nothing.
        machine.set_device_restricted(false).await.unwrap();
        assert_eq!(
            machine.store().get_secrets_from_inbox(&SecretName::RecoveryKey).await.unwrap().len(),
            1
        );

        machine.set_device_restricted(true).await.unwrap();
        assert!(
            machine
                .store()
                .get_secrets_from_inbox(&SecretName::RecoveryKey)
                .await
                .unwrap()
                .is_empty(),
            "the backup could otherwise be resumed with it"
        );
    }

    #[async_test]
    async fn test_a_queued_secret_request_is_not_sent_while_restricted() {
        use ruma::events::secret::request::SecretName;

        use crate::{gossiping::GossipMachine, store::types::Changes};

        let (alice, _) = get_machine_pair_with_session(alice_id(), bob_id(), false).await;

        // A request that was queued in the window around the flag being set,
        // or that is restored after a crash: it is in the store *after* the
        // flag, so `set_device_restricted` never saw it.
        alice.set_device_restricted(true).await.unwrap();
        alice
            .store()
            .save_changes(Changes {
                key_requests: GossipMachine::request_missing_secrets(
                    alice.user_id(),
                    vec![SecretName::RecoveryKey],
                ),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(unsent_secret_requests(&**alice.store()).await > 0);

        assert_eq!(secret_request_count(&alice).await, 0);

        // Control: without the restriction the same request goes out.
        alice.set_device_restricted(false).await.unwrap();
        assert!(secret_request_count(&alice).await > 0);
    }
}
