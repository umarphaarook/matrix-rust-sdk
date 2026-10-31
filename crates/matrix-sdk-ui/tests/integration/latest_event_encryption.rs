//! The latest event of a room reports how it reached us, with regard to
//! end-to-end encryption (`LatestEventValue::Remote::event_encryption`).
//!
//! A decrypted event and one sent in the clear carry the same `content`, so a
//! client can only tell them apart by this label.

use std::time::Duration;

use assert_matches2::assert_matches;
use matrix_sdk::{
    Client, Room, encryption::EncryptionSettings, test_utils::mocks::MatrixMockServer,
};
use matrix_sdk_test::{JoinedRoomBuilder, async_test, event_factory::EventFactory};
use matrix_sdk_ui::{
    notification_client::NotificationEventEncryption,
    timeline::{LatestEventValue, RoomExt as _},
};
use ruma::{
    RoomVersionId, device_id, event_id, events::AnySyncTimelineEvent, room_id, serde::Raw, user_id,
};
use tokio::time::sleep;

const ROOM_ID: &str = "!test:localhost";

/// Bob's side of a room Alice has just sent one encrypted message to, plus
/// everything needed to deliver it.
struct Rig {
    server: MatrixMockServer,
    bob: Client,
    bob_room: Room,
    /// Alice's encrypted event, as the server would deliver it to Bob.
    encrypted_event: Raw<AnySyncTimelineEvent>,
    /// The to-device event carrying the room key for that message.
    room_key: Raw<ruma::events::AnyToDeviceEvent>,
}

async fn rig(room_is_encrypted: bool) -> Rig {
    let room_id = room_id!("!test:localhost");
    assert_eq!(room_id.as_str(), ROOM_ID);
    let alice_user_id = user_id!("@alice:localhost");
    let bob_user_id = user_id!("@bob:localhost");

    let server = MatrixMockServer::new().await;
    server.mock_crypto_endpoints_preset().await;

    let encryption_settings =
        EncryptionSettings { auto_enable_cross_signing: true, ..Default::default() };

    let alice = server
        .client_builder_for_crypto_end_to_end(alice_user_id, device_id!("ALICEDEVICE"))
        .on_builder(|builder| {
            builder
                .with_enable_share_history_on_invite(true)
                .with_encryption_settings(encryption_settings)
        })
        .build()
        .await;
    let bob = server
        .client_builder_for_crypto_end_to_end(bob_user_id, device_id!("BOBDEVICE"))
        .on_builder(|builder| {
            builder
                .with_enable_share_history_on_invite(true)
                .with_encryption_settings(encryption_settings)
        })
        .build()
        .await;
    server.exchange_e2ee_identities(&alice, &bob).await;
    // The latest events are computed from the event cache.
    bob.event_cache().subscribe().unwrap();

    let f = EventFactory::new().room(room_id).sender(alice_user_id);
    let alice_member = f.member(alice_user_id).into_raw();
    let bob_member = f.member(bob_user_id).into_raw();

    // Alice's room is always encrypted so that she produces a real ciphertext;
    // Bob's room is what the test varies.
    let alice_room_builder = JoinedRoomBuilder::new(room_id)
        .add_state_event(f.create(alice_user_id, RoomVersionId::V1))
        .add_state_event(f.room_encryption());
    let mut bob_room_builder =
        JoinedRoomBuilder::new(room_id).add_state_event(f.create(alice_user_id, RoomVersionId::V1));
    if room_is_encrypted {
        bob_room_builder = bob_room_builder.add_state_event(f.room_encryption());
    }
    server
        .mock_sync()
        .ok_and_run(&alice, |b| {
            b.add_joined_room(alice_room_builder);
        })
        .await;
    server
        .mock_sync()
        .ok_and_run(&bob, |b| {
            b.add_joined_room(bob_room_builder);
        })
        .await;

    let alice_room = alice.get_room(room_id).unwrap();
    let bob_room = bob.get_room(room_id).unwrap();

    let (event_receiver, mock) =
        server.mock_room_send().ok_with_capture(event_id!("$secret"), alice_user_id);
    let (_guard, room_key) = server.mock_capture_put_to_device(alice_user_id).await;
    {
        let _guard = mock.mock_once().mount_as_scoped().await;
        server
            .mock_get_members()
            .ok(vec![alice_member.clone(), bob_member.clone()])
            .mock_once()
            .mount()
            .await;
        alice_room
            .send_raw("m.room.message", serde_json::json!({"body": "secret", "msgtype": "m.text"}))
            .await
            .unwrap();
    }
    let encrypted_event = event_receiver.await.unwrap();
    let room_key = room_key.await;

    Rig { server, bob, bob_room, encrypted_event, room_key: room_key.cast_unchecked() }
}

impl Rig {
    async fn deliver(&self, event: Raw<AnySyncTimelineEvent>) {
        let room_id = room_id!("!test:localhost");
        self.server
            .mock_sync()
            .ok_and_run(&self.bob, |b| {
                b.add_joined_room(JoinedRoomBuilder::new(room_id).add_timeline_event(event));
            })
            .await;
    }

    async fn deliver_room_key(&self) {
        self.server
            .mock_sync()
            .ok_and_run(&self.bob, |b| {
                b.add_to_device_event(self.room_key.deserialize_as().unwrap());
            })
            .await;
    }

    /// Start the latest-events task for the room, as the room list does.
    async fn listen(&self) {
        self.bob.latest_events().await.listen_to_room(room_id!("!test:localhost")).await.unwrap();
    }

    /// The label of the room's latest event, once it is a remote value.
    async fn encryption(&self) -> Option<NotificationEventEncryption> {
        // The latest events task computes the value in the background.
        for _ in 0..50 {
            if let LatestEventValue::Remote { event_encryption, .. } =
                self.bob_room.latest_event().await
            {
                return event_encryption;
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("the room never got a remote latest event");
    }

    /// Wait for the label to become `expected` (a redecryption re-emits it).
    async fn wait_for(&self, expected: NotificationEventEncryption) {
        for _ in 0..100 {
            if let LatestEventValue::Remote { event_encryption, .. } =
                self.bob_room.latest_event().await
                && event_encryption == Some(expected)
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("the latest event never reported {expected:?}");
    }
}

fn clear_message() -> Raw<AnySyncTimelineEvent> {
    EventFactory::new()
        .room(room_id!("!test:localhost"))
        .sender(user_id!("@alice:localhost"))
        .text_msg("forged")
        .event_id(event_id!("$clear"))
        .server_ts(1)
        .into_raw_sync()
}

#[async_test]
async fn test_plain_text_event_in_an_encrypted_room_is_not_encrypted() {
    let rig = rig(true).await;
    rig.listen().await;
    rig.deliver(clear_message()).await;

    assert_eq!(rig.encryption().await, Some(NotificationEventEncryption::NotEncrypted));
}

#[async_test]
async fn test_decrypted_event_is_decrypted() {
    let rig = rig(true).await;
    rig.listen().await;
    // The key arrives first, so the message decrypts on arrival.
    rig.deliver_room_key().await;
    rig.deliver(rig.encrypted_event.clone()).await;

    rig.wait_for(NotificationEventEncryption::Decrypted).await;
}

/// The latest-events task never picks an `m.room.encrypted` event (it is
/// "explicitly not suitable"), so an undecryptable message is never the latest
/// event and can never be labelled: the room keeps its previous value. The
/// `UnableToDecrypt` label itself is covered by the unit test of
/// `from_base_latest_event_value`.
#[async_test]
async fn test_undecryptable_event_is_not_the_latest_event() {
    let rig = rig(true).await;
    rig.listen().await;
    rig.deliver(rig.encrypted_event.clone()).await;
    sleep(Duration::from_millis(500)).await;

    assert_matches!(rig.bob_room.latest_event().await, LatestEventValue::None);
}

#[async_test]
async fn test_undecryptable_event_leaves_the_previous_label_alone() {
    let rig = rig(true).await;
    rig.listen().await;
    rig.deliver(clear_message()).await;
    assert_eq!(rig.encryption().await, Some(NotificationEventEncryption::NotEncrypted));

    rig.deliver(rig.encrypted_event.clone()).await;
    sleep(Duration::from_millis(500)).await;

    assert_eq!(rig.encryption().await, Some(NotificationEventEncryption::NotEncrypted));
}

#[async_test]
async fn test_late_room_key_turns_a_hidden_undecryptable_event_into_decrypted() {
    let rig = rig(true).await;
    rig.listen().await;
    rig.deliver(rig.encrypted_event.clone()).await;
    sleep(Duration::from_millis(300)).await;
    assert_matches!(rig.bob_room.latest_event().await, LatestEventValue::None);

    rig.deliver_room_key().await;

    // The redecrypted event becomes the latest event, labelled as decrypted.
    rig.wait_for(NotificationEventEncryption::Decrypted).await;
}
