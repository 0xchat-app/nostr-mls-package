// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.7.0.

// ignore_for_file: unused_import, unused_element, unnecessary_import, duplicate_ignore, invalid_use_of_internal_member, annotate_overrides, non_constant_identifier_names, curly_braces_in_flow_control_structures, prefer_const_literals_to_create_immutables, unused_field

import 'api/mls_api.dart';
import 'dart:async';
import 'dart:convert';
import 'frb_generated.dart';
import 'frb_generated.io.dart'
    if (dart.library.js_interop) 'frb_generated.web.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

/// Main entrypoint of the Rust API
class RustLib extends BaseEntrypoint<RustLibApi, RustLibApiImpl, RustLibWire> {
  @internal
  static final instance = RustLib._();

  RustLib._();

  /// Initialize flutter_rust_bridge
  static Future<void> init({
    RustLibApi? api,
    BaseHandler? handler,
    ExternalLibrary? externalLibrary,
  }) async {
    await instance.initImpl(
      api: api,
      handler: handler,
      externalLibrary: externalLibrary,
    );
  }

  /// Initialize flutter_rust_bridge in mock mode.
  /// No libraries for FFI are loaded.
  static void initMock({
    required RustLibApi api,
  }) {
    instance.initMockImpl(
      api: api,
    );
  }

  /// Dispose flutter_rust_bridge
  ///
  /// The call to this function is optional, since flutter_rust_bridge (and everything else)
  /// is automatically disposed when the app stops.
  static void dispose() => instance.disposeImpl();

  @override
  ApiImplConstructor<RustLibApiImpl, RustLibWire> get apiImplConstructor =>
      RustLibApiImpl.new;

  @override
  WireConstructor<RustLibWire> get wireConstructor =>
      RustLibWire.fromExternalLibrary;

  @override
  Future<void> executeRustInitializers() async {}

  @override
  ExternalLibraryLoaderConfig get defaultExternalLibraryLoaderConfig =>
      kDefaultExternalLibraryLoaderConfig;

  @override
  String get codegenVersion => '2.7.0';

  @override
  int get rustContentHash => 1209994060;

  static const kDefaultExternalLibraryLoaderConfig =
      ExternalLibraryLoaderConfig(
    stem: 'nostr_mls_package',
    ioDirectory: 'rust/target/release/',
    webPrefix: 'pkg/',
  );
}

abstract class RustLibApi extends BaseApi {
  Future<String> crateApiMlsApiAddMembers(
      {required List<int> groupId,
      required List<String> serializedKeyPackages});

  Future<String> crateApiMlsApiCommitProposal(
      {required List<int> groupId, required String proposal});

  Future<String> crateApiMlsApiCreateCommitMessageForGroup(
      {required String nostrGroupId,
      required List<int> serializedCommit,
      required U8Array32 secretKey});

  Future<String> crateApiMlsApiCreateGroup(
      {required String groupName,
      required String groupDescription,
      required List<String> groupMembersSerializedKeyPackages,
      required List<String> groupMembersPubkeys,
      required String groupCreatorPublicKey,
      required List<String> groupAdminPublicKeys,
      required List<String> relays});

  Future<String> crateApiMlsApiCreateKeyPackageForEvent(
      {required String publicKey, List<String>? relay, String? client});

  Future<String> crateApiMlsApiCreateMessageForGroup(
      {required List<int> groupId, required String rumorEventString});

  Future<String> crateApiMlsApiExportSecret({required List<int> groupId});

  Future<String> crateApiMlsApiFindEncodedKeypackageFromWelcomeEvent(
      {required List<String> encodedKeypackages,
      required List<int> wrapperEventId,
      required String rumorEventString});

  Future<String> crateApiMlsApiGetCiphersuite();

  Future<String> crateApiMlsApiGetExtensions();

  Future<String> crateApiMlsApiGetGroup({required List<int> groupId});

  Future<String> crateApiMlsApiGetKeyPackageFromStorage(
      {required String serializedKeyPackage});

  Future<String> crateApiMlsApiGetMembers({required List<int> groupId});

  Future<String> crateApiMlsApiInitNostrMls(
      {required String path, String? identity, String? password});

  Future<String> crateApiMlsApiJoinGroupFromWelcome(
      {required List<int> wrapperEventId, required String rumorEventString});

  Future<String> crateApiMlsApiLeaveGroup({required List<int> groupId});

  Future<String> crateApiMlsApiPreviewGroupFromWelcome(
      {required List<int> wrapperEventId, required String rumorEventString});

  Future<String> crateApiMlsApiProcessMessageForGroup(
      {required String eventString});

  Future<String> crateApiMlsApiRemoveMembers(
      {required List<int> groupId, required List<String> memberPubkeys});
}

class RustLibApiImpl extends RustLibApiImplPlatform implements RustLibApi {
  RustLibApiImpl({
    required super.handler,
    required super.wire,
    required super.generalizedFrbRustBinding,
    required super.portManager,
  });

  @override
  Future<String> crateApiMlsApiAddMembers(
      {required List<int> groupId,
      required List<String> serializedKeyPackages}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        sse_encode_list_String(serializedKeyPackages, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 1, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiAddMembersConstMeta,
      argValues: [groupId, serializedKeyPackages],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiAddMembersConstMeta => const TaskConstMeta(
        debugName: "add_members",
        argNames: ["groupId", "serializedKeyPackages"],
      );

  @override
  Future<String> crateApiMlsApiCommitProposal(
      {required List<int> groupId, required String proposal}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        sse_encode_String(proposal, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 2, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiCommitProposalConstMeta,
      argValues: [groupId, proposal],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiCommitProposalConstMeta =>
      const TaskConstMeta(
        debugName: "commit_proposal",
        argNames: ["groupId", "proposal"],
      );

  @override
  Future<String> crateApiMlsApiCreateCommitMessageForGroup(
      {required String nostrGroupId,
      required List<int> serializedCommit,
      required U8Array32 secretKey}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(nostrGroupId, serializer);
        sse_encode_list_prim_u_8_loose(serializedCommit, serializer);
        sse_encode_u_8_array_32(secretKey, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 3, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiCreateCommitMessageForGroupConstMeta,
      argValues: [nostrGroupId, serializedCommit, secretKey],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiCreateCommitMessageForGroupConstMeta =>
      const TaskConstMeta(
        debugName: "create_commit_message_for_group",
        argNames: ["nostrGroupId", "serializedCommit", "secretKey"],
      );

  @override
  Future<String> crateApiMlsApiCreateGroup(
      {required String groupName,
      required String groupDescription,
      required List<String> groupMembersSerializedKeyPackages,
      required List<String> groupMembersPubkeys,
      required String groupCreatorPublicKey,
      required List<String> groupAdminPublicKeys,
      required List<String> relays}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(groupName, serializer);
        sse_encode_String(groupDescription, serializer);
        sse_encode_list_String(groupMembersSerializedKeyPackages, serializer);
        sse_encode_list_String(groupMembersPubkeys, serializer);
        sse_encode_String(groupCreatorPublicKey, serializer);
        sse_encode_list_String(groupAdminPublicKeys, serializer);
        sse_encode_list_String(relays, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 4, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiCreateGroupConstMeta,
      argValues: [
        groupName,
        groupDescription,
        groupMembersSerializedKeyPackages,
        groupMembersPubkeys,
        groupCreatorPublicKey,
        groupAdminPublicKeys,
        relays
      ],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiCreateGroupConstMeta => const TaskConstMeta(
        debugName: "create_group",
        argNames: [
          "groupName",
          "groupDescription",
          "groupMembersSerializedKeyPackages",
          "groupMembersPubkeys",
          "groupCreatorPublicKey",
          "groupAdminPublicKeys",
          "relays"
        ],
      );

  @override
  Future<String> crateApiMlsApiCreateKeyPackageForEvent(
      {required String publicKey, List<String>? relay, String? client}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(publicKey, serializer);
        sse_encode_opt_list_String(relay, serializer);
        sse_encode_opt_String(client, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 5, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiCreateKeyPackageForEventConstMeta,
      argValues: [publicKey, relay, client],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiCreateKeyPackageForEventConstMeta =>
      const TaskConstMeta(
        debugName: "create_key_package_for_event",
        argNames: ["publicKey", "relay", "client"],
      );

  @override
  Future<String> crateApiMlsApiCreateMessageForGroup(
      {required List<int> groupId, required String rumorEventString}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        sse_encode_String(rumorEventString, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 6, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiCreateMessageForGroupConstMeta,
      argValues: [groupId, rumorEventString],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiCreateMessageForGroupConstMeta =>
      const TaskConstMeta(
        debugName: "create_message_for_group",
        argNames: ["groupId", "rumorEventString"],
      );

  @override
  Future<String> crateApiMlsApiExportSecret({required List<int> groupId}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 7, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiExportSecretConstMeta,
      argValues: [groupId],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiExportSecretConstMeta => const TaskConstMeta(
        debugName: "export_secret",
        argNames: ["groupId"],
      );

  @override
  Future<String> crateApiMlsApiFindEncodedKeypackageFromWelcomeEvent(
      {required List<String> encodedKeypackages,
      required List<int> wrapperEventId,
      required String rumorEventString}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_String(encodedKeypackages, serializer);
        sse_encode_list_prim_u_8_loose(wrapperEventId, serializer);
        sse_encode_String(rumorEventString, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 8, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiFindEncodedKeypackageFromWelcomeEventConstMeta,
      argValues: [encodedKeypackages, wrapperEventId, rumorEventString],
      apiImpl: this,
    ));
  }

  TaskConstMeta
      get kCrateApiMlsApiFindEncodedKeypackageFromWelcomeEventConstMeta =>
          const TaskConstMeta(
            debugName: "find_encoded_keypackage_from_welcome_event",
            argNames: [
              "encodedKeypackages",
              "wrapperEventId",
              "rumorEventString"
            ],
          );

  @override
  Future<String> crateApiMlsApiGetCiphersuite() {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 9, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiGetCiphersuiteConstMeta,
      argValues: [],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiGetCiphersuiteConstMeta =>
      const TaskConstMeta(
        debugName: "get_ciphersuite",
        argNames: [],
      );

  @override
  Future<String> crateApiMlsApiGetExtensions() {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 10, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiGetExtensionsConstMeta,
      argValues: [],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiGetExtensionsConstMeta =>
      const TaskConstMeta(
        debugName: "get_extensions",
        argNames: [],
      );

  @override
  Future<String> crateApiMlsApiGetGroup({required List<int> groupId}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 11, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiGetGroupConstMeta,
      argValues: [groupId],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiGetGroupConstMeta => const TaskConstMeta(
        debugName: "get_group",
        argNames: ["groupId"],
      );

  @override
  Future<String> crateApiMlsApiGetKeyPackageFromStorage(
      {required String serializedKeyPackage}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(serializedKeyPackage, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 12, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiGetKeyPackageFromStorageConstMeta,
      argValues: [serializedKeyPackage],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiGetKeyPackageFromStorageConstMeta =>
      const TaskConstMeta(
        debugName: "get_key_package_from_storage",
        argNames: ["serializedKeyPackage"],
      );

  @override
  Future<String> crateApiMlsApiGetMembers({required List<int> groupId}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 13, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiGetMembersConstMeta,
      argValues: [groupId],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiGetMembersConstMeta => const TaskConstMeta(
        debugName: "get_members",
        argNames: ["groupId"],
      );

  @override
  Future<String> crateApiMlsApiInitNostrMls(
      {required String path, String? identity, String? password}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(path, serializer);
        sse_encode_opt_String(identity, serializer);
        sse_encode_opt_String(password, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 14, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiInitNostrMlsConstMeta,
      argValues: [path, identity, password],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiInitNostrMlsConstMeta => const TaskConstMeta(
        debugName: "init_nostr_mls",
        argNames: ["path", "identity", "password"],
      );

  @override
  Future<String> crateApiMlsApiJoinGroupFromWelcome(
      {required List<int> wrapperEventId, required String rumorEventString}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(wrapperEventId, serializer);
        sse_encode_String(rumorEventString, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 15, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiJoinGroupFromWelcomeConstMeta,
      argValues: [wrapperEventId, rumorEventString],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiJoinGroupFromWelcomeConstMeta =>
      const TaskConstMeta(
        debugName: "join_group_from_welcome",
        argNames: ["wrapperEventId", "rumorEventString"],
      );

  @override
  Future<String> crateApiMlsApiLeaveGroup({required List<int> groupId}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 16, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiLeaveGroupConstMeta,
      argValues: [groupId],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiLeaveGroupConstMeta => const TaskConstMeta(
        debugName: "leave_group",
        argNames: ["groupId"],
      );

  @override
  Future<String> crateApiMlsApiPreviewGroupFromWelcome(
      {required List<int> wrapperEventId, required String rumorEventString}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(wrapperEventId, serializer);
        sse_encode_String(rumorEventString, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 17, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiPreviewGroupFromWelcomeConstMeta,
      argValues: [wrapperEventId, rumorEventString],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiPreviewGroupFromWelcomeConstMeta =>
      const TaskConstMeta(
        debugName: "preview_group_from_welcome",
        argNames: ["wrapperEventId", "rumorEventString"],
      );

  @override
  Future<String> crateApiMlsApiProcessMessageForGroup(
      {required String eventString}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(eventString, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 18, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiProcessMessageForGroupConstMeta,
      argValues: [eventString],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiProcessMessageForGroupConstMeta =>
      const TaskConstMeta(
        debugName: "process_message_for_group",
        argNames: ["eventString"],
      );

  @override
  Future<String> crateApiMlsApiRemoveMembers(
      {required List<int> groupId, required List<String> memberPubkeys}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        sse_encode_list_String(memberPubkeys, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 19, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiRemoveMembersConstMeta,
      argValues: [groupId, memberPubkeys],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiRemoveMembersConstMeta =>
      const TaskConstMeta(
        debugName: "remove_members",
        argNames: ["groupId", "memberPubkeys"],
      );

  @protected
  AnyhowException dco_decode_AnyhowException(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return AnyhowException(raw as String);
  }

  @protected
  String dco_decode_String(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw as String;
  }

  @protected
  List<String> dco_decode_list_String(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return (raw as List<dynamic>).map(dco_decode_String).toList();
  }

  @protected
  List<int> dco_decode_list_prim_u_8_loose(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw as List<int>;
  }

  @protected
  Uint8List dco_decode_list_prim_u_8_strict(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw as Uint8List;
  }

  @protected
  String? dco_decode_opt_String(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw == null ? null : dco_decode_String(raw);
  }

  @protected
  List<String>? dco_decode_opt_list_String(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw == null ? null : dco_decode_list_String(raw);
  }

  @protected
  int dco_decode_u_8(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw as int;
  }

  @protected
  U8Array32 dco_decode_u_8_array_32(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return U8Array32(dco_decode_list_prim_u_8_strict(raw));
  }

  @protected
  AnyhowException sse_decode_AnyhowException(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    var inner = sse_decode_String(deserializer);
    return AnyhowException(inner);
  }

  @protected
  String sse_decode_String(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    var inner = sse_decode_list_prim_u_8_strict(deserializer);
    return utf8.decoder.convert(inner);
  }

  @protected
  List<String> sse_decode_list_String(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs

    var len_ = sse_decode_i_32(deserializer);
    var ans_ = <String>[];
    for (var idx_ = 0; idx_ < len_; ++idx_) {
      ans_.add(sse_decode_String(deserializer));
    }
    return ans_;
  }

  @protected
  List<int> sse_decode_list_prim_u_8_loose(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    var len_ = sse_decode_i_32(deserializer);
    return deserializer.buffer.getUint8List(len_);
  }

  @protected
  Uint8List sse_decode_list_prim_u_8_strict(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    var len_ = sse_decode_i_32(deserializer);
    return deserializer.buffer.getUint8List(len_);
  }

  @protected
  String? sse_decode_opt_String(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs

    if (sse_decode_bool(deserializer)) {
      return (sse_decode_String(deserializer));
    } else {
      return null;
    }
  }

  @protected
  List<String>? sse_decode_opt_list_String(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs

    if (sse_decode_bool(deserializer)) {
      return (sse_decode_list_String(deserializer));
    } else {
      return null;
    }
  }

  @protected
  int sse_decode_u_8(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return deserializer.buffer.getUint8();
  }

  @protected
  U8Array32 sse_decode_u_8_array_32(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    var inner = sse_decode_list_prim_u_8_strict(deserializer);
    return U8Array32(inner);
  }

  @protected
  int sse_decode_i_32(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return deserializer.buffer.getInt32();
  }

  @protected
  bool sse_decode_bool(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return deserializer.buffer.getUint8() != 0;
  }

  @protected
  void sse_encode_AnyhowException(
      AnyhowException self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_String(self.message, serializer);
  }

  @protected
  void sse_encode_String(String self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_list_prim_u_8_strict(utf8.encoder.convert(self), serializer);
  }

  @protected
  void sse_encode_list_String(List<String> self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_i_32(self.length, serializer);
    for (final item in self) {
      sse_encode_String(item, serializer);
    }
  }

  @protected
  void sse_encode_list_prim_u_8_loose(
      List<int> self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_i_32(self.length, serializer);
    serializer.buffer
        .putUint8List(self is Uint8List ? self : Uint8List.fromList(self));
  }

  @protected
  void sse_encode_list_prim_u_8_strict(
      Uint8List self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_i_32(self.length, serializer);
    serializer.buffer.putUint8List(self);
  }

  @protected
  void sse_encode_opt_String(String? self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs

    sse_encode_bool(self != null, serializer);
    if (self != null) {
      sse_encode_String(self, serializer);
    }
  }

  @protected
  void sse_encode_opt_list_String(
      List<String>? self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs

    sse_encode_bool(self != null, serializer);
    if (self != null) {
      sse_encode_list_String(self, serializer);
    }
  }

  @protected
  void sse_encode_u_8(int self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    serializer.buffer.putUint8(self);
  }

  @protected
  void sse_encode_u_8_array_32(U8Array32 self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_list_prim_u_8_strict(self.inner, serializer);
  }

  @protected
  void sse_encode_i_32(int self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    serializer.buffer.putInt32(self);
  }

  @protected
  void sse_encode_bool(bool self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    serializer.buffer.putUint8(self ? 1 : 0);
  }
}
