// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.7.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../frb_generated.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

// These types are ignored because they are not used by any `pub` functions: `NOSTR_MLS`
// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `deref`, `initialize`

Future<void> initNostrMls({required String path, String? identity}) =>
    RustLib.instance.api
        .crateApiMlsApiInitNostrMls(path: path, identity: identity);

String getCiphersuite() => RustLib.instance.api.crateApiMlsApiGetCiphersuite();

List<String> getExtensions() =>
    RustLib.instance.api.crateApiMlsApiGetExtensions();

Future<String> createKeyPackageForEvent({required String publicKey}) =>
    RustLib.instance.api
        .crateApiMlsApiCreateKeyPackageForEvent(publicKey: publicKey);

Future<String> parseKeyPackage({required String encodedKeyPackage}) =>
    RustLib.instance.api
        .crateApiMlsApiParseKeyPackage(encodedKeyPackage: encodedKeyPackage);

Future<String> deleteKeyPackageFromStorage(
        {required String encodedKeyPackage}) =>
    RustLib.instance.api.crateApiMlsApiDeleteKeyPackageFromStorage(
        encodedKeyPackage: encodedKeyPackage);

Future<String> loadKeyPackageFromStorage({required String encodedKeyPackage}) =>
    RustLib.instance.api.crateApiMlsApiLoadKeyPackageFromStorage(
        encodedKeyPackage: encodedKeyPackage);

Future<String> createGroup(
        {required String groupName,
        required String groupDescription,
        required List<String> groupMembersKeyPackages,
        required String groupCreatorPublicKey,
        required List<String> groupAdminPublicKeys,
        required List<String> relays}) =>
    RustLib.instance.api.crateApiMlsApiCreateGroup(
        groupName: groupName,
        groupDescription: groupDescription,
        groupMembersKeyPackages: groupMembersKeyPackages,
        groupCreatorPublicKey: groupCreatorPublicKey,
        groupAdminPublicKeys: groupAdminPublicKeys,
        relays: relays);

Future<Uint8List> createMessageForGroup(
        {required List<int> groupId, required String messageEvent}) =>
    RustLib.instance.api.crateApiMlsApiCreateMessageForGroup(
        groupId: groupId, messageEvent: messageEvent);

Future<(String, BigInt)> exportSecretAsHexSecretKeyAndEpoch(
        {required List<int> groupId}) =>
    RustLib.instance.api
        .crateApiMlsApiExportSecretAsHexSecretKeyAndEpoch(groupId: groupId);

Future<Uint8List> processMessageForGroup(
        {required List<int> groupId, required List<int> serializedMessage}) =>
    RustLib.instance.api.crateApiMlsApiProcessMessageForGroup(
        groupId: groupId, serializedMessage: serializedMessage);

Future<String> previewWelcomeEvent(
        {required List<int> serializedWelcomeMessage}) =>
    RustLib.instance.api.crateApiMlsApiPreviewWelcomeEvent(
        serializedWelcomeMessage: serializedWelcomeMessage);

Future<String> joinGroupFromWelcome(
        {required List<int> serializedWelcomeMessage}) =>
    RustLib.instance.api.crateApiMlsApiJoinGroupFromWelcome(
        serializedWelcomeMessage: serializedWelcomeMessage);
