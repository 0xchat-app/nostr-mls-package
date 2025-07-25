// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.7.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../frb_generated.dart';
import 'package:collection/collection.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

// These types are ignored because they are not used by any `pub` functions: `NOSTR_MLS`
// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `deref`, `initialize`

/// Initialize the NostrMls instance
/// Returns: JSON {"status": "success"} on success, or error message on failure
Future<String> initNostrMls(
        {required String path, String? identity, String? password}) =>
    RustLib.instance.api.crateApiMlsApiInitNostrMls(
        path: path, identity: identity, password: password);

/// Get the current ciphersuite
/// Returns: JSON formatted ciphersuite information
Future<String> getCiphersuite() =>
    RustLib.instance.api.crateApiMlsApiGetCiphersuite();

/// Get the list of enabled extensions
/// Returns: JSON formatted list of extensions
Future<String> getExtensions() =>
    RustLib.instance.api.crateApiMlsApiGetExtensions();

/// Create a key package for an event
/// Returns: JSON formatted key package information, including encoded key package and tags
Future<String> createKeyPackageForEvent(
        {required String publicKey, List<String>? relay, String? client}) =>
    RustLib.instance.api.crateApiMlsApiCreateKeyPackageForEvent(
        publicKey: publicKey, relay: relay, client: client);

/// Create a group
/// Returns: JSON formatted group information
Future<String> createGroup(
        {required String groupName,
        required String groupDescription,
        required List<String> groupMembersSerializedKeyPackages,
        required List<String> groupMembersPubkeys,
        required String groupCreatorPublicKey,
        required List<String> groupAdminPublicKeys,
        required List<String> relays}) =>
    RustLib.instance.api.crateApiMlsApiCreateGroup(
        groupName: groupName,
        groupDescription: groupDescription,
        groupMembersSerializedKeyPackages: groupMembersSerializedKeyPackages,
        groupMembersPubkeys: groupMembersPubkeys,
        groupCreatorPublicKey: groupCreatorPublicKey,
        groupAdminPublicKeys: groupAdminPublicKeys,
        relays: relays);

/// Create a message for a group
/// Parameters: group_id - byte array of group ID, rumor_event_string - JSON string of the event
/// Returns: JSON formatted message information
Future<String> createMessageForGroup(
        {required List<int> groupId, required String rumorEventString}) =>
    RustLib.instance.api.crateApiMlsApiCreateMessageForGroup(
        groupId: groupId, rumorEventString: rumorEventString);

/// Create a commit message for a group
/// Parameters: group_id - byte array of group ID, serialized_commit - serialized commit
/// Returns: JSON formatted message information
Future<String> createCommitMessageForGroup(
        {required String nostrGroupId,
        required List<int> serializedCommit,
        required U8Array32 secretKey}) =>
    RustLib.instance.api.crateApiMlsApiCreateCommitMessageForGroup(
        nostrGroupId: nostrGroupId,
        serializedCommit: serializedCommit,
        secretKey: secretKey);

/// Export group secret
/// Parameters: group_id - byte array of group ID
/// Returns: JSON formatted secret information, including secret key and epoch
Future<String> exportSecret({required List<int> groupId}) =>
    RustLib.instance.api.crateApiMlsApiExportSecret(groupId: groupId);

/// Process a message for a group
/// Parameters: group_id - byte array of group ID, serialized_message - serialized message
/// Returns: JSON formatted processing result
Future<String> processMessageForGroup({required String eventString}) =>
    RustLib.instance.api
        .crateApiMlsApiProcessMessageForGroup(eventString: eventString);

/// Preview a group from a welcome message without joining it
/// Parameters: wrapper_event_id - byte array of event ID, rumor_event_string - JSON string of the event
/// Returns: JSON formatted group preview information
Future<String> previewGroupFromWelcome(
        {required List<int> wrapperEventId,
        required String rumorEventString}) =>
    RustLib.instance.api.crateApiMlsApiPreviewGroupFromWelcome(
        wrapperEventId: wrapperEventId, rumorEventString: rumorEventString);

/// Join a group from a welcome message
/// Parameters: wrapper_event_id - byte array of event ID, rumor_event_string - JSON string of the event
/// Returns: JSON formatted join result
Future<String> joinGroupFromWelcome(
        {required List<int> wrapperEventId,
        required String rumorEventString}) =>
    RustLib.instance.api.crateApiMlsApiJoinGroupFromWelcome(
        wrapperEventId: wrapperEventId, rumorEventString: rumorEventString);

Future<String> getMembers({required List<int> groupId}) =>
    RustLib.instance.api.crateApiMlsApiGetMembers(groupId: groupId);

/// Get group information by group ID
/// Parameters: group_id - byte array of group ID
/// Returns: JSON formatted group information including group ID, members, and nostr group data
Future<String> getGroup({required List<int> groupId}) =>
    RustLib.instance.api.crateApiMlsApiGetGroup(groupId: groupId);

/// Add members to an existing group
/// Parameters: group_id - byte array of group ID, serialized_key_packages - array of serialized key packages
/// Returns: JSON formatted result containing serialized commit and welcome messages
Future<String> addMembers(
        {required List<int> groupId,
        required List<String> serializedKeyPackages}) =>
    RustLib.instance.api.crateApiMlsApiAddMembers(
        groupId: groupId, serializedKeyPackages: serializedKeyPackages);

/// Remove members from a group
/// Parameters: group_id - byte array of group ID, member_pubkeys - array of member public keys to remove
/// Returns: JSON formatted result containing serialized commit message
Future<String> removeMembers(
        {required List<int> groupId, required List<String> memberPubkeys}) =>
    RustLib.instance.api.crateApiMlsApiRemoveMembers(
        groupId: groupId, memberPubkeys: memberPubkeys);

/// Commit a proposal
/// Parameters: group_id - byte array of group ID, proposal - serialized proposal
/// Returns: JSON formatted result containing commit and welcome messages
Future<String> commitProposal(
        {required List<int> groupId, required String proposal}) =>
    RustLib.instance.api
        .crateApiMlsApiCommitProposal(groupId: groupId, proposal: proposal);

/// Leave a group
/// Parameters: group_id - byte array of group ID
/// Returns: JSON formatted result containing serialized leave message
Future<String> leaveGroup({required List<int> groupId}) =>
    RustLib.instance.api.crateApiMlsApiLeaveGroup(groupId: groupId);

/// Get key package from storage
/// Parameters: serialized_key_package - serialized key package string
/// Returns: JSON formatted key package information
Future<String> getKeyPackageFromStorage(
        {required String serializedKeyPackage}) =>
    RustLib.instance.api.crateApiMlsApiGetKeyPackageFromStorage(
        serializedKeyPackage: serializedKeyPackage);

/// Find encoded key package from welcome event
/// Parameters: encoded_keypackages - array of encoded key package strings, wrapper_event_id - byte array of event ID, rumor_event_string - JSON string of the event
/// Returns: JSON formatted result containing the matched key package index and info if found
Future<String> findEncodedKeypackageFromWelcomeEvent(
        {required List<String> encodedKeypackages,
        required List<int> wrapperEventId,
        required String rumorEventString}) =>
    RustLib.instance.api.crateApiMlsApiFindEncodedKeypackageFromWelcomeEvent(
        encodedKeypackages: encodedKeypackages,
        wrapperEventId: wrapperEventId,
        rumorEventString: rumorEventString);

class U8Array32 extends NonGrowableListView<int> {
  static const arraySize = 32;

  @internal
  Uint8List get inner => _inner;
  final Uint8List _inner;

  U8Array32(this._inner)
      : assert(_inner.length == arraySize),
        super(_inner);

  U8Array32.init() : this(Uint8List(arraySize));
}
