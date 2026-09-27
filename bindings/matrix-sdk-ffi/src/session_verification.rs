// Copyright 2025 The Matrix.org Foundation C.I.C.
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
// See the License for that specific language governing permissions and
// limitations under the License.

use std::sync::{Arc, RwLock};

use futures_util::{Stream, StreamExt, future, stream};
use matrix_sdk::{
    Account,
    encryption::{
        Encryption,
        identities::UserIdentity,
        verification::{SasState, SasVerification, VerificationRequest, VerificationRequestState},
    },
    ruma::events::key::verification::VerificationMethod,
};
use matrix_sdk_common::{SendOutsideWasm, SyncOutsideWasm};
use ruma::UserId;
use tracing::error;

use crate::{
    client::UserProfile, error::ClientError, runtime::get_runtime_handle, utils::Timestamp,
};

#[derive(uniffi::Object)]
pub struct SessionVerificationEmoji {
    symbol: String,
    description: String,
}

#[matrix_sdk_ffi_macros::export]
impl SessionVerificationEmoji {
    pub fn symbol(&self) -> String {
        self.symbol.clone()
    }

    pub fn description(&self) -> String {
        self.description.clone()
    }
}

#[derive(uniffi::Enum)]
pub enum SessionVerificationData {
    Emojis { emojis: Vec<Arc<SessionVerificationEmoji>>, indices: Vec<u8> },
    Decimals { values: Vec<u16> },
}

/// Details about the incoming verification request
#[derive(uniffi::Record)]
pub struct SessionVerificationRequestDetails {
    sender_profile: UserProfile,
    flow_id: String,
    device_id: String,
    device_display_name: Option<String>,
    /// First time this device was seen in milliseconds since epoch.
    first_seen_timestamp: Timestamp,
}

#[matrix_sdk_ffi_macros::export(callback_interface)]
pub trait SessionVerificationControllerDelegate: SyncOutsideWasm + SendOutsideWasm {
    fn did_receive_verification_request(&self, details: SessionVerificationRequestDetails);
    fn did_accept_verification_request(&self);
    fn did_start_sas_verification(&self);
    fn did_receive_verification_data(&self, data: SessionVerificationData);
    fn did_fail(&self);
    fn did_cancel(&self, code: String);
    fn did_finish(&self);
}

pub type Delegate = Arc<RwLock<Option<Arc<dyn SessionVerificationControllerDelegate>>>>;

/// SDK `changes()` streams omit the current value. Subscribe before taking the
/// snapshot, then suppress a duplicate snapshot/change of the same protocol phase.
fn verification_states<T>(
    initial: T,
    changes: impl Stream<Item = T>,
    deduplicate: impl Fn(&T) -> bool,
) -> impl Stream<Item = T> {
    stream::iter([initial])
        .chain(changes)
        .scan(None, move |previous, state| {
            let phase = std::mem::discriminant(&state);
            let changed = !deduplicate(&state) || previous.as_ref() != Some(&phase);
            *previous = Some(phase);
            future::ready(Some(changed.then_some(state)))
        })
        .filter_map(future::ready)
}

#[derive(Clone, uniffi::Object)]
pub struct SessionVerificationController {
    encryption: Encryption,
    user_identity: UserIdentity,
    account: Account,
    delegate: Delegate,
    verification_request: Arc<RwLock<Option<VerificationRequest>>>,
    request_delegate: Arc<RwLock<Delegate>>,
    sas_verification: Arc<RwLock<Option<SasVerification>>>,
}

#[matrix_sdk_ffi_macros::export]
impl SessionVerificationController {
    pub fn set_delegate(&self, delegate: Option<Box<dyn SessionVerificationControllerDelegate>>) {
        *self.request_delegate.read().unwrap().write().unwrap() = None;
        *self.delegate.write().unwrap() = delegate.map(Arc::from);
    }

    /// Set this particular request as the currently active one and register for
    /// events pertaining it.
    /// * `sender_id` - The user requesting verification.
    /// * `flow_id` - - The ID that uniquely identifies the verification flow.
    pub async fn acknowledge_verification_request(
        &self,
        sender_id: String,
        flow_id: String,
    ) -> Result<(), ClientError> {
        let sender_id = UserId::parse(sender_id.clone())?;

        let verification_request = self
            .encryption
            .get_verification_request(&sender_id, flow_id)
            .await
            .ok_or(ClientError::from_str("Unknown session verification request", None))?;

        self.set_ongoing_verification_request(verification_request)
    }

    /// Accept the previously acknowledged verification request
    pub async fn accept_verification_request(&self) -> Result<(), ClientError> {
        let verification_request = self.verification_request.read().unwrap().clone();

        if let Some(verification_request) = verification_request {
            let methods = vec![VerificationMethod::SasV1];
            verification_request.accept_with_methods(methods).await?;
        }

        Ok(())
    }

    /// Request verification for the current device
    pub async fn request_device_verification(&self) -> Result<(), ClientError> {
        let methods = vec![VerificationMethod::SasV1];
        let verification_request =
            self.user_identity.request_verification_with_methods(methods).await?;

        self.set_ongoing_verification_request(verification_request)
    }

    /// Request verification for the given user
    pub async fn request_user_verification(&self, user_id: String) -> Result<(), ClientError> {
        let user_id = UserId::parse(user_id)?;

        let user_identity = self
            .encryption
            .get_user_identity(&user_id)
            .await?
            .ok_or(ClientError::from_str("Unknown user identity", None))?;

        if user_identity.is_verified() {
            return Err(ClientError::from_str("User is already verified", None));
        }

        let methods = vec![VerificationMethod::SasV1];

        let verification_request = user_identity.request_verification_with_methods(methods).await?;

        self.set_ongoing_verification_request(verification_request)
    }

    /// Transition the current verification request into a SAS verification
    /// flow.
    pub async fn start_sas_verification(&self) -> Result<(), ClientError> {
        let (verification_request, delegate) = {
            let request = self.verification_request.read().unwrap();
            (request.clone(), self.request_delegate.read().unwrap().clone())
        };

        let Some(verification_request) = verification_request else {
            return Err(ClientError::from_str("Verification request missing.", None));
        };

        match verification_request.start_sas().await {
            Ok(Some(verification)) => {
                {
                    let scope = delegate.read().unwrap();
                    if scope.is_none() {
                        return Ok(());
                    }
                    *self.sas_verification.write().unwrap() = Some(verification.clone());
                }

                if let Some(delegate) = Self::current_delegate(&delegate) {
                    delegate.did_start_sas_verification()
                }

                get_runtime_handle()
                    .spawn(Self::listen_to_sas_verification_changes(verification, delegate));
            }
            _ => {
                if let Some(delegate) = Self::current_delegate(&delegate) {
                    delegate.did_fail()
                }
            }
        }

        Ok(())
    }

    /// Confirm that the short auth strings match on both sides.
    pub async fn approve_verification(&self) -> Result<(), ClientError> {
        let sas_verification = self.sas_verification.read().unwrap().clone();

        let Some(sas_verification) = sas_verification else {
            return Err(ClientError::from_str("SAS verification missing", None));
        };

        Ok(sas_verification.confirm().await?)
    }

    /// Reject the short auth string
    pub async fn decline_verification(&self) -> Result<(), ClientError> {
        let sas_verification = self.sas_verification.read().unwrap().clone();

        let Some(sas_verification) = sas_verification else {
            return Err(ClientError::from_str("SAS verification missing", None));
        };

        Ok(sas_verification.mismatch().await?)
    }

    /// Cancel the current verification request
    pub async fn cancel_verification(&self) -> Result<(), ClientError> {
        let verification_request = self.verification_request.read().unwrap().clone();

        let Some(verification_request) = verification_request else {
            return Err(ClientError::from_str("Verification request missing.", None));
        };

        Ok(verification_request.cancel().await?)
    }
}

impl SessionVerificationController {
    pub(crate) fn new(
        encryption: Encryption,
        user_identity: UserIdentity,
        account: Account,
    ) -> Self {
        SessionVerificationController {
            encryption,
            user_identity,
            account,
            delegate: Arc::new(RwLock::new(None)),
            verification_request: Arc::new(RwLock::new(None)),
            request_delegate: Arc::new(RwLock::new(Arc::new(RwLock::new(None)))),
            sas_verification: Arc::new(RwLock::new(None)),
        }
    }

    /// Ask the controller to process an incoming request based on the sender
    /// and flow identifier. It will fetch the request, verify that it's in the
    /// correct state and then and notify the delegate.
    pub(crate) async fn process_incoming_verification_request(
        &self,
        sender: &UserId,
        flow_id: impl AsRef<str>,
    ) {
        let cross_signing_status = self.encryption.cross_signing_status().await;

        if sender != self.user_identity.user_id() {
            if !cross_signing_status.as_ref().is_some_and(|status| status.is_complete()) {
                error!(
                    "Cannot verify other users until our own device's cross-signing status \
                     is complete: {cross_signing_status:?}"
                );
                return;
            }
        } else if !cross_signing_status.as_ref().is_some_and(|status| status.has_self_signing) {
            // Signing one of our own devices needs the private self-signing key. Not
            // having it is only fine while we are the session that is about to be
            // verified. If we are already verified the flow could only fail, so
            // don't surface the request at all.
            let we_are_verified = self
                .encryption
                .get_own_device()
                .await
                .ok()
                .flatten()
                .is_some_and(|device| device.is_cross_signed_by_owner());

            if we_are_verified {
                error!(
                    "Cannot verify another one of our devices, this session is missing \
                     the private self-signing key: {cross_signing_status:?}"
                );
                return;
            }
        }

        let Some(request) = self.encryption.get_verification_request(sender, flow_id).await else {
            error!("Failed retrieving verification request");
            return;
        };

        let VerificationRequestState::Requested { other_device_data, .. } = request.state() else {
            error!("Received verification request event but the request is in the wrong state.");
            return;
        };

        // Claim the local observation slot only when no different request is
        // active. An offered request has not been accepted on the wire, but it
        // must already be watched for cancellation by another account device.
        if self.verification_request.read().unwrap().as_ref().is_some_and(|active| {
            !active.is_done() && !active.is_cancelled() && active.flow_id() != request.flow_id()
        }) {
            return;
        }

        let Ok(sender_profile) = UserProfile::fetch(&self.account, sender).await else {
            error!("Failed fetching user profile for verification request");
            return;
        };

        if let Some(delegate) = Self::current_delegate(&self.delegate) {
            delegate.did_receive_verification_request(SessionVerificationRequestDetails {
                sender_profile,
                flow_id: request.flow_id().into(),
                device_id: other_device_data.device_id().into(),
                device_display_name: other_device_data.display_name().map(str::to_owned),
                first_seen_timestamp: other_device_data.first_time_seen_ts().into(),
            });
            // The callback installs the new attempt-scoped delegate. Register
            // the request listener afterward so it captures that delegate.
            if let Err(error) = self.set_ongoing_verification_request(request) {
                error!("Failed observing incoming verification request: {error}");
            }
        }
    }

    fn set_ongoing_verification_request(
        &self,
        verification_request: VerificationRequest,
    ) -> Result<(), ClientError> {
        let mut active_request = self.verification_request.write().unwrap();
        if let Some(ongoing_verification_request) = active_request.as_ref() {
            if ongoing_verification_request.flow_id() == verification_request.flow_id()
                && ongoing_verification_request.other_user_id()
                    == verification_request.other_user_id()
            {
                return Ok(());
            }
            if !ongoing_verification_request.is_done()
                && !ongoing_verification_request.is_cancelled()
            {
                return Err(ClientError::from_str(
                    "There is another verification flow ongoing.",
                    None,
                ));
            }
        }

        let delegate = Self::replace_request_delegate(&self.request_delegate, &self.delegate);
        *self.sas_verification.write().unwrap() = None;
        *active_request = Some(verification_request.clone());

        get_runtime_handle().spawn(Self::listen_to_verification_request_changes(
            verification_request,
            self.sas_verification.clone(),
            delegate,
        ));

        Ok(())
    }

    /// Retire the previous request's delivery slot before installing a new one.
    /// Each listener retains its own slot, never the mutable app-global delegate.
    fn replace_request_delegate(active: &Arc<RwLock<Delegate>>, delegate: &Delegate) -> Delegate {
        let mut active = active.write().unwrap();
        *active.write().unwrap() = None;
        let next = Arc::new(RwLock::new(Self::current_delegate(delegate)));
        *active = next.clone();
        next
    }

    /// Clone the current delegate out of the lock, releasing the read guard
    /// before it is returned. Callbacks must never be invoked while the guard
    /// is held: a delegate that detaches itself via `set_delegate` (which takes
    /// the write guard) would otherwise deadlock. See issue #6669.
    fn current_delegate(
        delegate: &Delegate,
    ) -> Option<Arc<dyn SessionVerificationControllerDelegate>> {
        delegate.read().unwrap().clone()
    }

    async fn listen_to_verification_request_changes(
        verification_request: VerificationRequest,
        sas_verification: Arc<RwLock<Option<SasVerification>>>,
        delegate: Delegate,
    ) {
        let changes = verification_request.changes();
        let mut stream =
            Box::pin(verification_states(verification_request.state(), changes, |state| {
                // A protocol transition can replace the SAS object during simultaneous
                // start resolution. Never discard that payload merely for sharing a phase.
                !matches!(state, VerificationRequestState::Transitioned { .. })
            }));

        while let Some(state) = stream.next().await {
            match state {
                VerificationRequestState::Transitioned { verification } => {
                    let Some(verification) = verification.sas() else {
                        error!("Invalid, non-sas verification flow. Returning.");
                        return;
                    };

                    {
                        let scope = delegate.read().unwrap();
                        if scope.is_none() {
                            return;
                        }
                        *sas_verification.write().unwrap() = Some(verification.clone());
                    }

                    if verification.accept().await.is_ok() {
                        if let Some(current_delegate) = Self::current_delegate(&delegate) {
                            current_delegate.did_start_sas_verification()
                        }

                        get_runtime_handle().spawn(Self::listen_to_sas_verification_changes(
                            verification,
                            delegate.clone(),
                        ));
                    } else if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_fail()
                    }
                }
                VerificationRequestState::Ready { .. } => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_accept_verification_request()
                    }
                }
                VerificationRequestState::Cancelled(cancel_info) => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_cancel(cancel_info.cancel_code().as_str().to_owned());
                    }
                }
                _ => {}
            }
        }
    }

    async fn listen_to_sas_verification_changes(sas: SasVerification, delegate: Delegate) {
        let changes = sas.changes();
        let mut stream = Box::pin(verification_states(sas.state(), changes, |_| true));

        while let Some(state) = stream.next().await {
            match state {
                SasState::KeysExchanged { emojis, decimals } => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        if let Some(emojis) = emojis {
                            current_delegate.did_receive_verification_data(
                                SessionVerificationData::Emojis {
                                    emojis: emojis
                                        .emojis
                                        .into_iter()
                                        .map(|emoji| {
                                            Arc::new(SessionVerificationEmoji {
                                                symbol: emoji.symbol.to_owned(),
                                                description: emoji.description.to_owned(),
                                            })
                                        })
                                        .collect(),
                                    indices: emojis.indices.to_vec(),
                                },
                            );
                        } else {
                            current_delegate.did_receive_verification_data(
                                SessionVerificationData::Decimals {
                                    values: vec![decimals.0, decimals.1, decimals.2],
                                },
                            )
                        }
                    }
                }
                SasState::Done { .. } => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_finish()
                    }
                    break;
                }
                SasState::Cancelled(cancel_info) => {
                    if let Some(current_delegate) = Self::current_delegate(&delegate) {
                        current_delegate.did_cancel(cancel_info.cancel_code().as_str().to_owned())
                    }
                    break;
                }
                SasState::Created { .. }
                | SasState::Started { .. }
                | SasState::Accepted { .. }
                | SasState::Confirmed => (),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use super::{
        Delegate, SessionVerificationController, SessionVerificationControllerDelegate,
        SessionVerificationData, SessionVerificationRequestDetails,
    };

    /// A delegate that detaches itself from within a callback. The only
    /// documented way to detach is `set_delegate(None)`, which takes the
    /// delegate write guard. Mirrors the deadlock repro from issue #6669.
    struct ReentrantDelegate {
        slot: Delegate,
    }

    impl SessionVerificationControllerDelegate for ReentrantDelegate {
        fn did_cancel(&self, _code: String) {
            *self.slot.write().unwrap() = None;
        }
        fn did_receive_verification_request(&self, _: SessionVerificationRequestDetails) {}
        fn did_accept_verification_request(&self) {}
        fn did_start_sas_verification(&self) {}
        fn did_receive_verification_data(&self, _: SessionVerificationData) {}
        fn did_fail(&self) {}
        fn did_finish(&self) {}
    }

    #[tokio::test]
    async fn already_exchanged_sas_is_delivered_without_another_state_change() {
        use futures_util::{FutureExt, StreamExt, stream};
        #[derive(Debug, PartialEq)]
        enum Phase {
            KeysExchanged,
        }
        // A plain SDK changes stream has no initial emission, matching the live
        // peer-at-SAS / app-at-Ready reproduction.
        assert!(stream::pending::<Phase>().next().now_or_never().is_none());
        let mut states =
            Box::pin(super::verification_states(Phase::KeysExchanged, stream::pending(), |_| true));
        assert_eq!(states.next().now_or_never(), Some(Some(Phase::KeysExchanged)));
    }

    #[tokio::test]
    async fn snapshot_change_overlap_does_not_repeat_ready_or_comparison() {
        use futures_util::{StreamExt, stream};
        #[derive(Debug, PartialEq)]
        enum Phase {
            Ready,
            KeysExchanged,
            Done,
        }
        let changes =
            stream::iter([Phase::Ready, Phase::KeysExchanged, Phase::KeysExchanged, Phase::Done]);
        let states: Vec<_> =
            super::verification_states(Phase::Ready, changes, |_| true).collect().await;
        assert_eq!(states, [Phase::Ready, Phase::KeysExchanged, Phase::Done]);
    }

    #[tokio::test]
    async fn distinct_protocol_transition_payloads_are_preserved() {
        use futures_util::{StreamExt, stream};
        #[derive(Debug, PartialEq)]
        enum Phase {
            Transitioned(u8),
        }
        let states: Vec<_> = super::verification_states(
            Phase::Transitioned(1),
            stream::iter([Phase::Transitioned(2)]),
            |_| false,
        )
        .collect()
        .await;
        assert_eq!(states, [Phase::Transitioned(1), Phase::Transitioned(2)]);
    }

    #[test]
    fn replacing_a_request_retires_its_listener_delegate() {
        let root: Delegate = Arc::new(RwLock::new(None));
        *root.write().unwrap() = Some(Arc::new(ReentrantDelegate { slot: root.clone() }));
        let active = Arc::new(RwLock::new(root.clone()));
        // Start with an independent empty request slot, not the root itself.
        *active.write().unwrap() = Arc::new(RwLock::new(None));
        let old_listener = SessionVerificationController::replace_request_delegate(&active, &root);
        assert!(SessionVerificationController::current_delegate(&old_listener).is_some());
        let new_listener = SessionVerificationController::replace_request_delegate(&active, &root);
        assert!(SessionVerificationController::current_delegate(&old_listener).is_none());
        assert!(SessionVerificationController::current_delegate(&new_listener).is_some());
        assert!(SessionVerificationController::current_delegate(&root).is_some());
    }

    #[test]
    fn invoking_a_callback_does_not_hold_the_delegate_read_guard() {
        let slot: Delegate = Arc::new(RwLock::new(None));
        *slot.write().unwrap() = Some(Arc::new(ReentrantDelegate { slot: slot.clone() }));

        // `current_delegate` must release the read guard before the callback
        // runs. If it held the guard, the re-entrant `set_delegate` (write
        // guard) inside `did_cancel` would deadlock here.
        if let Some(delegate) = SessionVerificationController::current_delegate(&slot) {
            delegate.did_cancel("m.user".to_owned());
        }

        assert!(slot.read().unwrap().is_none(), "delegate should have detached itself");
    }
}
