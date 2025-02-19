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
  int get rustContentHash => -1537393424;

  static const kDefaultExternalLibraryLoaderConfig =
      ExternalLibraryLoaderConfig(
    stem: 'nostr_mls_package',
    ioDirectory: 'rust/target/release/',
    webPrefix: 'pkg/',
  );
}

abstract class RustLibApi extends BaseApi {
  Future<String> crateApiMlsApiCreateGroup(
      {required String groupName,
      required String groupDescription,
      required List<String> groupMembersKeyPackages,
      required String groupCreatorPublicKey,
      required List<String> groupAdminPublicKeys,
      required List<String> relays});

  Future<String> crateApiMlsApiCreateKeyPackageForEvent(
      {required String publicKey});

  Future<Uint8List> crateApiMlsApiCreateMessageForGroup(
      {required List<int> groupId, required String messageEvent});

  Future<String> crateApiMlsApiDeleteKeyPackageFromStorage(
      {required String encodedKeyPackage});

  Future<(String, BigInt)> crateApiMlsApiExportSecretAsHexSecretKeyAndEpoch(
      {required List<int> groupId});

  String crateApiMlsApiGetCiphersuite();

  List<String> crateApiMlsApiGetExtensions();

  Future<void> crateApiMlsApiInitNostrMls(
      {required String path, String? identity});

  Future<String> crateApiMlsApiJoinGroupFromWelcome(
      {required List<int> serializedWelcomeMessage});

  Future<String> crateApiMlsApiParseKeyPackage(
      {required String encodedKeyPackage});

  Future<String> crateApiMlsApiPreviewWelcomeEvent(
      {required List<int> serializedWelcomeMessage});

  Future<Uint8List> crateApiMlsApiProcessMessageForGroup(
      {required List<int> groupId, required List<int> serializedMessage});
}

class RustLibApiImpl extends RustLibApiImplPlatform implements RustLibApi {
  RustLibApiImpl({
    required super.handler,
    required super.wire,
    required super.generalizedFrbRustBinding,
    required super.portManager,
  });

  @override
  Future<String> crateApiMlsApiCreateGroup(
      {required String groupName,
      required String groupDescription,
      required List<String> groupMembersKeyPackages,
      required String groupCreatorPublicKey,
      required List<String> groupAdminPublicKeys,
      required List<String> relays}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(groupName, serializer);
        sse_encode_String(groupDescription, serializer);
        sse_encode_list_String(groupMembersKeyPackages, serializer);
        sse_encode_String(groupCreatorPublicKey, serializer);
        sse_encode_list_String(groupAdminPublicKeys, serializer);
        sse_encode_list_String(relays, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 1, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: null,
      ),
      constMeta: kCrateApiMlsApiCreateGroupConstMeta,
      argValues: [
        groupName,
        groupDescription,
        groupMembersKeyPackages,
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
          "groupMembersKeyPackages",
          "groupCreatorPublicKey",
          "groupAdminPublicKeys",
          "relays"
        ],
      );

  @override
  Future<String> crateApiMlsApiCreateKeyPackageForEvent(
      {required String publicKey}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(publicKey, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 2, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: null,
      ),
      constMeta: kCrateApiMlsApiCreateKeyPackageForEventConstMeta,
      argValues: [publicKey],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiCreateKeyPackageForEventConstMeta =>
      const TaskConstMeta(
        debugName: "create_key_package_for_event",
        argNames: ["publicKey"],
      );

  @override
  Future<Uint8List> crateApiMlsApiCreateMessageForGroup(
      {required List<int> groupId, required String messageEvent}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        sse_encode_String(messageEvent, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 3, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_list_prim_u_8_strict,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiCreateMessageForGroupConstMeta,
      argValues: [groupId, messageEvent],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiCreateMessageForGroupConstMeta =>
      const TaskConstMeta(
        debugName: "create_message_for_group",
        argNames: ["groupId", "messageEvent"],
      );

  @override
  Future<String> crateApiMlsApiDeleteKeyPackageFromStorage(
      {required String encodedKeyPackage}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(encodedKeyPackage, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 4, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: null,
      ),
      constMeta: kCrateApiMlsApiDeleteKeyPackageFromStorageConstMeta,
      argValues: [encodedKeyPackage],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiDeleteKeyPackageFromStorageConstMeta =>
      const TaskConstMeta(
        debugName: "delete_key_package_from_storage",
        argNames: ["encodedKeyPackage"],
      );

  @override
  Future<(String, BigInt)> crateApiMlsApiExportSecretAsHexSecretKeyAndEpoch(
      {required List<int> groupId}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 5, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_record_string_u_64,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiExportSecretAsHexSecretKeyAndEpochConstMeta,
      argValues: [groupId],
      apiImpl: this,
    ));
  }

  TaskConstMeta
      get kCrateApiMlsApiExportSecretAsHexSecretKeyAndEpochConstMeta =>
          const TaskConstMeta(
            debugName: "export_secret_as_hex_secret_key_and_epoch",
            argNames: ["groupId"],
          );

  @override
  String crateApiMlsApiGetCiphersuite() {
    return handler.executeSync(SyncTask(
      callFfi: () {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        return pdeCallFfi(generalizedFrbRustBinding, serializer, funcId: 6)!;
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: null,
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
  List<String> crateApiMlsApiGetExtensions() {
    return handler.executeSync(SyncTask(
      callFfi: () {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        return pdeCallFfi(generalizedFrbRustBinding, serializer, funcId: 7)!;
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_list_String,
        decodeErrorData: null,
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
  Future<void> crateApiMlsApiInitNostrMls(
      {required String path, String? identity}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(path, serializer);
        sse_encode_opt_String(identity, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 8, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_unit,
        decodeErrorData: null,
      ),
      constMeta: kCrateApiMlsApiInitNostrMlsConstMeta,
      argValues: [path, identity],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiInitNostrMlsConstMeta => const TaskConstMeta(
        debugName: "init_nostr_mls",
        argNames: ["path", "identity"],
      );

  @override
  Future<String> crateApiMlsApiJoinGroupFromWelcome(
      {required List<int> serializedWelcomeMessage}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(serializedWelcomeMessage, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 9, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiJoinGroupFromWelcomeConstMeta,
      argValues: [serializedWelcomeMessage],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiJoinGroupFromWelcomeConstMeta =>
      const TaskConstMeta(
        debugName: "join_group_from_welcome",
        argNames: ["serializedWelcomeMessage"],
      );

  @override
  Future<String> crateApiMlsApiParseKeyPackage(
      {required String encodedKeyPackage}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(encodedKeyPackage, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 10, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: null,
      ),
      constMeta: kCrateApiMlsApiParseKeyPackageConstMeta,
      argValues: [encodedKeyPackage],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiParseKeyPackageConstMeta =>
      const TaskConstMeta(
        debugName: "parse_key_package",
        argNames: ["encodedKeyPackage"],
      );

  @override
  Future<String> crateApiMlsApiPreviewWelcomeEvent(
      {required List<int> serializedWelcomeMessage}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(serializedWelcomeMessage, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 11, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiPreviewWelcomeEventConstMeta,
      argValues: [serializedWelcomeMessage],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiPreviewWelcomeEventConstMeta =>
      const TaskConstMeta(
        debugName: "preview_welcome_event",
        argNames: ["serializedWelcomeMessage"],
      );

  @override
  Future<Uint8List> crateApiMlsApiProcessMessageForGroup(
      {required List<int> groupId, required List<int> serializedMessage}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_list_prim_u_8_loose(groupId, serializer);
        sse_encode_list_prim_u_8_loose(serializedMessage, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 12, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_list_prim_u_8_strict,
        decodeErrorData: sse_decode_AnyhowException,
      ),
      constMeta: kCrateApiMlsApiProcessMessageForGroupConstMeta,
      argValues: [groupId, serializedMessage],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiMlsApiProcessMessageForGroupConstMeta =>
      const TaskConstMeta(
        debugName: "process_message_for_group",
        argNames: ["groupId", "serializedMessage"],
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
  (String, BigInt) dco_decode_record_string_u_64(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    final arr = raw as List<dynamic>;
    if (arr.length != 2) {
      throw Exception('Expected 2 elements, got ${arr.length}');
    }
    return (
      dco_decode_String(arr[0]),
      dco_decode_u_64(arr[1]),
    );
  }

  @protected
  BigInt dco_decode_u_64(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return dcoDecodeU64(raw);
  }

  @protected
  int dco_decode_u_8(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw as int;
  }

  @protected
  void dco_decode_unit(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return;
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
  (String, BigInt) sse_decode_record_string_u_64(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    var var_field0 = sse_decode_String(deserializer);
    var var_field1 = sse_decode_u_64(deserializer);
    return (var_field0, var_field1);
  }

  @protected
  BigInt sse_decode_u_64(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return deserializer.buffer.getBigUint64();
  }

  @protected
  int sse_decode_u_8(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return deserializer.buffer.getUint8();
  }

  @protected
  void sse_decode_unit(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
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
  void sse_encode_record_string_u_64(
      (String, BigInt) self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_String(self.$1, serializer);
    sse_encode_u_64(self.$2, serializer);
  }

  @protected
  void sse_encode_u_64(BigInt self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    serializer.buffer.putBigUint64(self);
  }

  @protected
  void sse_encode_u_8(int self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    serializer.buffer.putUint8(self);
  }

  @protected
  void sse_encode_unit(void self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
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
