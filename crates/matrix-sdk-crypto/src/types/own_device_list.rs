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

//! The signed list of a user's own devices.
//!
//! The list says which of the user's devices are the user's *own*: the devices
//! that may be handed the account's secrets and older message keys. It is
//! signed with the user's self-signing key, which only devices holding the
//! account's secrets have, so neither a borrowed device nor the homeserver can
//! produce a valid one. It carries a version that only ever increases.
//!
//! This module holds the data type, its canonical form, and signature
//! verification. Where the list is stored on the server, and when a device
//! decides to trust or serve from it, are decided elsewhere.

use std::collections::BTreeMap;

use ruma::{DeviceId, OwnedDeviceId, OwnedUserId, UserId};
use serde::{Deserialize, Serialize};
use vodozemac::Ed25519PublicKey;

use super::{Signatures, cross_signing::SelfSigningPubkey};
use crate::{error::SignatureError, olm::SignedJsonObject, store::CryptoStoreError};

/// The largest version that survives canonical JSON, which only carries
/// integers up to 2^53 - 1.
const MAX_VERSION: u64 = (1 << 53) - 1;

/// Serde for the device map: the keys are written as unpadded base64 strings,
/// which is also what the canonical JSON the signature covers contains.
mod key_map {
    use std::collections::BTreeMap;

    use ruma::OwnedDeviceId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
    use vodozemac::Ed25519PublicKey;

    pub fn serialize<S: Serializer>(
        devices: &BTreeMap<OwnedDeviceId, Ed25519PublicKey>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        devices
            .iter()
            .map(|(id, key)| (id, key.to_base64()))
            .collect::<BTreeMap<_, _>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<OwnedDeviceId, Ed25519PublicKey>, D::Error> {
        BTreeMap::<OwnedDeviceId, String>::deserialize(deserializer)?
            .into_iter()
            .map(|(id, key)| {
                Ed25519PublicKey::from_base64(&key).map(|key| (id, key)).map_err(D::Error::custom)
            })
            .collect()
    }
}

/// The version of the list's signed format. It is part of the signed content,
/// and a device refuses any other value, so a change of format is a lockstep
/// upgrade that fails closed on devices that have not made it.
pub const OWN_DEVICE_LIST_FORMAT: u32 = 1;

/// The role marker inside the signed content.
///
/// The self-signing key also signs device keys, so every signature over a
/// list is bound to this marker: a signature made for some other object can
/// not be replayed as a list, and the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Purpose {
    #[serde(rename = "own_device_list")]
    OwnDeviceList,
}

/// A signed list of a user's own devices.
///
/// The JSON form is:
///
/// ```json
/// {
///   "purpose": "own_device_list",
///   "format": 1,
///   "user_id": "@alice:example.org",
///   "version": 3,
///   "devices": { "ABCDEFGH": "<ed25519 key>", "IJKLMNOP": "<ed25519 key>" },
///   "signatures": { "@alice:example.org": { "ed25519:<self-signing key>": "..." } }
/// }
/// ```
///
/// `devices` maps each own device's ID to its Ed25519 identity key. A device
/// is on the list only if both match: a device ID alone proves nothing, since
/// a new device can be given the ID of a deleted one. The map has a single
/// canonical order, and everything except `signatures` (and `unsigned`, which
/// is not kept) is covered by the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnDeviceList {
    purpose: Purpose,
    format: u32,
    user_id: OwnedUserId,
    version: u64,
    #[serde(with = "key_map")]
    devices: BTreeMap<OwnedDeviceId, Ed25519PublicKey>,
    #[serde(default)]
    signatures: Signatures,
}

impl OwnDeviceList {
    /// Create an unsigned list.
    ///
    /// Use [`OlmMachine::sign_own_device_list`](crate::OlmMachine) to obtain a
    /// signed one.
    pub(crate) fn new(
        user_id: OwnedUserId,
        version: u64,
        devices: BTreeMap<OwnedDeviceId, Ed25519PublicKey>,
    ) -> Self {
        Self {
            purpose: Purpose::OwnDeviceList,
            format: OWN_DEVICE_LIST_FORMAT,
            user_id,
            version,
            devices,
            signatures: Signatures::new(),
        }
    }

    /// The user the list belongs to.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The version of the list. Only ever increases.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The devices on the list, with their Ed25519 identity keys.
    pub fn devices(&self) -> &BTreeMap<OwnedDeviceId, Ed25519PublicKey> {
        &self.devices
    }

    /// Is a device with this ID and this Ed25519 key on the list?
    ///
    /// This says nothing about whether the list itself is valid.
    pub fn contains(&self, device_id: &DeviceId, ed25519_key: &Ed25519PublicKey) -> bool {
        self.devices.get(device_id) == Some(ed25519_key)
    }

    /// The signatures on the list.
    pub fn signatures(&self) -> &Signatures {
        &self.signatures
    }

    pub(crate) fn signatures_mut(&mut self) -> &mut Signatures {
        &mut self.signatures
    }

    /// Check the list's form and its signature against `self_signing_key`, the
    /// self-signing key of the user the list claims to belong to.
    ///
    /// The caller decides which key to trust; for a device that serves secrets
    /// that is the self-signing key of its own, verified, user identity.
    pub fn verify(&self, self_signing_key: &SelfSigningPubkey) -> Result<(), OwnDeviceListError> {
        if self.format != OWN_DEVICE_LIST_FORMAT {
            return Err(OwnDeviceListError::UnsupportedFormat(self.format));
        }

        if self.version == 0 || self.version > MAX_VERSION {
            return Err(OwnDeviceListError::InvalidVersion(self.version));
        }

        if self.user_id != self_signing_key.user_id() {
            return Err(OwnDeviceListError::WrongUser);
        }

        self_signing_key.verify_signed_object(self)?;

        Ok(())
    }
}

impl SignedJsonObject for OwnDeviceList {
    fn signatures(&self) -> &Signatures {
        &self.signatures
    }
}

/// Errors from signing, verifying or storing an own-device list.
#[derive(Debug, thiserror::Error)]
pub enum OwnDeviceListError {
    /// The list belongs to a different user than the key it was checked
    /// against.
    #[error("the own-device list belongs to a different user")]
    WrongUser,

    /// The list is in a format this device does not know.
    #[error("the own-device list format {0} is not supported")]
    UnsupportedFormat(u32),

    /// The version is zero, or too large to be signed.
    #[error("the own-device list version {0} is not valid")]
    InvalidVersion(u64),

    /// The signature is missing or does not verify.
    #[error("the own-device list signature is not valid: {0}")]
    Signature(#[from] SignatureError),

    /// This device is restricted and so can not change the list.
    #[error("this device is restricted and can not change the own-device list")]
    Restricted,

    /// The requested version is not above the highest version this device has
    /// accepted, so the list would be refused, by this device and by every
    /// other device that has seen the higher one.
    #[error(
        "the own-device list version {requested} is not above the highest version seen, {seen}"
    )]
    VersionNotAboveSeen {
        /// The highest version this device has accepted.
        seen: u64,
        /// The version that was requested.
        requested: u64,
    },

    /// A list was signed but this device does not accept it as its own, so
    /// signing it would leave this device out of step with the list it
    /// published.
    #[error("the signed own-device list was not accepted: {0:?}")]
    NotAccepted(crate::OwnDeviceListOutcome),

    /// This device does not hold the private keys of the current cross-signing
    /// identity.
    #[error("this device does not hold the account's current cross-signing secrets")]
    SecretsNotHeld,

    /// This device has no own user identity to check the list against.
    #[error("there is no own user identity to check the own-device list against")]
    NoOwnIdentity,

    /// The crypto store failed.
    #[error(transparent)]
    Store(#[from] CryptoStoreError),
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use matrix_sdk_test::async_test;
    use ruma::{OwnedDeviceId, device_id, user_id};
    use serde_json::json;
    use vodozemac::{Ed25519PublicKey, Ed25519SecretKey};

    use super::{OwnDeviceList, OwnDeviceListError};
    use crate::{
        OwnUserIdentityData,
        error::SignatureError,
        olm::{PrivateCrossSigningIdentity, SignedJsonObject},
        types::SelfSigningPubkey,
    };

    /// A deterministic Ed25519 key for a made-up device ID, so that tests can
    /// say "the same device" and "another device with the same ID".
    pub(crate) fn key(id: &str) -> Ed25519PublicKey {
        let mut seed = [0u8; 32];
        for (i, byte) in id.bytes().enumerate() {
            seed[i % 32] ^= byte.wrapping_add(i as u8);
        }
        Ed25519SecretKey::from_slice(&seed).public_key()
    }

    pub(crate) fn devices(ids: &[&str]) -> BTreeMap<OwnedDeviceId, Ed25519PublicKey> {
        ids.iter().map(|id| (OwnedDeviceId::from(*id), key(id))).collect()
    }

    /// A fresh own identity: the private keys (what an own device holds) and
    /// the matching public self-signing key (what any device checks against).
    async fn identity(user: &ruma::UserId) -> (PrivateCrossSigningIdentity, SelfSigningPubkey) {
        let private = PrivateCrossSigningIdentity::new(user.to_owned());
        let public = OwnUserIdentityData::from_private(&private).await;
        (private, public.self_signing_key().clone())
    }

    async fn signed(
        private: &PrivateCrossSigningIdentity,
        version: u64,
        ids: &[&str],
    ) -> OwnDeviceList {
        let mut list =
            OwnDeviceList::new(user_id!("@alice:example.org").to_owned(), version, devices(ids));
        private.sign_own_device_list(&mut list).await.unwrap();
        list
    }

    #[async_test]
    async fn test_signed_list_verifies() {
        let (private, public) = identity(user_id!("@alice:example.org")).await;
        let list = signed(&private, 3, &["B", "A"]).await;

        list.verify(&public).unwrap();
        assert_eq!(list.version(), 3);
        assert!(list.contains(device_id!("A"), &key("A")));
        assert!(list.contains(device_id!("B"), &key("B")));
        assert!(!list.contains(device_id!("C"), &key("C")));

        // The ID alone is not enough: the key has to be the one that was signed.
        assert!(!list.contains(device_id!("A"), &key("B")));
        assert!(!list.contains(device_id!("A"), &Ed25519SecretKey::new().public_key()));
    }

    #[async_test]
    async fn test_canonical_form_is_stable_and_excludes_the_signature() {
        let (private, _) = identity(user_id!("@alice:example.org")).await;

        // The order the devices were given in does not matter, and signing
        // leaves the canonical form (the signed bytes) untouched.
        let one = signed(&private, 3, &["B", "A"]).await;
        let two = signed(&private, 3, &["A", "B"]).await;

        let expected = format!(
            r#"{{"devices":{{"A":"{}","B":"{}"}},"format":1,"purpose":"own_device_list","user_id":"@alice:example.org","version":3}}"#,
            key("A").to_base64(),
            key("B").to_base64(),
        );
        assert_eq!(one.to_canonical_json().unwrap(), expected);
        assert_eq!(two.to_canonical_json().unwrap(), expected);
    }

    #[async_test]
    async fn test_json_round_trip_keeps_the_signature_valid() {
        let (private, public) = identity(user_id!("@alice:example.org")).await;
        let list = signed(&private, 1, &["A"]).await;

        let json = serde_json::to_value(&list).unwrap();
        assert_eq!(json["purpose"], "own_device_list");
        assert_eq!(json["devices"], json!({ "A": key("A").to_base64() }));
        assert_eq!(json["format"], 1);

        let parsed: OwnDeviceList = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, list);
        parsed.verify(&public).unwrap();
    }

    #[async_test]
    async fn test_altered_list_does_not_verify() {
        let (private, public) = identity(user_id!("@alice:example.org")).await;
        let list = signed(&private, 2, &["A"]).await;
        let json = serde_json::to_value(&list).unwrap();

        // A server or a borrowed device that edits any signed field.
        let mut with_extra_device = json.clone();
        with_extra_device["devices"] =
            json!({ "A": key("A").to_base64(), "BORROWED": key("BORROWED").to_base64() });
        let mut with_swapped_key = json.clone();
        with_swapped_key["devices"] = json!({ "A": key("BORROWED").to_base64() });
        let mut with_other_format = json.clone();
        with_other_format["format"] = json!(2);
        let mut with_higher_version = json.clone();
        with_higher_version["version"] = json!(99);
        let mut for_other_user = json;
        for_other_user["user_id"] = json!("@mallory:example.org");

        for forged in [
            with_extra_device,
            with_swapped_key,
            with_other_format,
            with_higher_version,
            for_other_user,
        ] {
            let forged: OwnDeviceList = serde_json::from_value(forged).unwrap();
            assert!(forged.verify(&public).is_err(), "a forged list verified: {forged:?}");
        }
    }

    #[async_test]
    async fn test_list_without_a_signature_does_not_verify() {
        let (_, public) = identity(user_id!("@alice:example.org")).await;
        let unsigned =
            OwnDeviceList::new(user_id!("@alice:example.org").to_owned(), 1, devices(&["A"]));

        assert_matches2::assert_matches!(
            unsigned.verify(&public),
            Err(OwnDeviceListError::Signature(SignatureError::NoSignatureFound))
        );
    }

    #[async_test]
    async fn test_list_signed_by_another_key_does_not_verify() {
        let (_, public) = identity(user_id!("@alice:example.org")).await;

        // Signed by a different identity of the same user: a borrowed device
        // that made its own cross-signing keys, or a server with its own.
        let (other_private, _) = identity(user_id!("@alice:example.org")).await;
        let list = signed(&other_private, 1, &["A", "BORROWED"]).await;
        assert!(list.verify(&public).is_err());

        // Signed with a device key placed under the self-signing key id.
        let mut list =
            OwnDeviceList::new(user_id!("@alice:example.org").to_owned(), 1, devices(&["A"]));
        let device_key = Ed25519SecretKey::new();
        let signature = crate::olm::utility::SignJson::sign_json(
            &device_key,
            ruma::canonical_json::to_canonical_value(&list).unwrap(),
        )
        .unwrap();
        let key_id = (&public).into_iter().next().unwrap().0.to_owned();
        list.signatures_mut().add_signature(
            user_id!("@alice:example.org").to_owned(),
            key_id,
            signature,
        );
        assert!(list.verify(&public).is_err());
    }

    #[async_test]
    async fn test_list_signed_under_another_key_id_does_not_verify() {
        let (private, public) = identity(user_id!("@alice:example.org")).await;
        let mut list = signed(&private, 1, &["A"]).await;

        // Move the (valid) signature under a key id the self-signing key does
        // not have, e.g. the master key's.
        let signature = list
            .signatures()
            .get(user_id!("@alice:example.org"))
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone()
            .unwrap();
        list.signatures_mut().clear();
        list.signatures_mut().add_signature(
            user_id!("@alice:example.org").to_owned(),
            ruma::DeviceKeyId::from_parts(
                ruma::DeviceKeyAlgorithm::Ed25519,
                device_id!("MASTERKEYID"),
            ),
            signature,
        );

        assert!(list.verify(&public).is_err());
    }

    #[async_test]
    async fn test_list_of_another_user_does_not_verify() {
        let (private, _) = identity(user_id!("@alice:example.org")).await;
        let (_, bobs_key) = identity(user_id!("@bob:example.org")).await;
        let list = signed(&private, 1, &["A"]).await;

        assert_matches2::assert_matches!(
            list.verify(&bobs_key),
            Err(OwnDeviceListError::WrongUser)
        );
    }

    #[async_test]
    async fn test_version_bounds() {
        let (private, public) = identity(user_id!("@alice:example.org")).await;

        // Zero is never valid, and the largest signable version still is.
        let zero = signed(&private, 0, &["A"]).await;
        assert_matches2::assert_matches!(
            zero.verify(&public),
            Err(OwnDeviceListError::InvalidVersion(0))
        );

        let largest = signed(&private, (1 << 53) - 1, &["A"]).await;
        largest.verify(&public).unwrap();

        // Above that the canonical form can not carry the number, so it can
        // not be signed at all.
        let mut too_big =
            OwnDeviceList::new(user_id!("@alice:example.org").to_owned(), 1 << 53, devices(&["A"]));
        assert!(private.sign_own_device_list(&mut too_big).await.is_err());
    }

    #[test]
    fn test_other_documents_are_not_lists() {
        // The role marker must be present and exact, so the self-signing key's
        // signature over device keys can never be read as a list.
        for json in [
            json!({"format": 1, "user_id": "@alice:example.org", "version": 1, "devices": {}}),
            json!({"purpose": "device", "format": 1, "user_id": "@alice:example.org", "version": 1, "devices": {}}),
        ] {
            assert!(serde_json::from_value::<OwnDeviceList>(json).is_err());
        }
    }

    #[async_test]
    async fn test_signing_needs_the_self_signing_key() {
        // A device that does not hold the account's secrets, such as a
        // borrowed one, can not sign a list.
        let empty = PrivateCrossSigningIdentity::empty(user_id!("@alice:example.org"));
        let mut list =
            OwnDeviceList::new(user_id!("@alice:example.org").to_owned(), 1, devices(&["A"]));

        assert_matches2::assert_matches!(
            empty.sign_own_device_list(&mut list).await,
            Err(SignatureError::MissingSigningKey)
        );
        assert!(list.signatures().is_empty());
    }
}
