// AUTO GENERATED FILE, DO NOT EDIT.
//
// Generated by `package:ffigen`.
// ignore_for_file: type=lint
import 'dart:ffi' as ffi;

class NativeLibrary {
  /// Holds the symbol lookup function.
  final ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
      _lookup;

  /// The symbols are looked up in [dynamicLibrary].
  NativeLibrary(ffi.DynamicLibrary dynamicLibrary)
      : _lookup = dynamicLibrary.lookup;

  /// The symbols are looked up with [lookup].
  NativeLibrary.fromLookup(
      ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
          lookup)
      : _lookup = lookup;

  void Free(
    ffi.Pointer<ffi.Uint8> pointer,
  ) {
    return _Free(
      pointer,
    );
  }

  late final _FreePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Uint8>)>>(
          'Free');
  late final _Free =
      _FreePtr.asFunction<void Function(ffi.Pointer<ffi.Uint8>)>();

  void Init() {
    return _Init();
  }

  late final _InitPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function()>>('Init');
  late final _Init = _InitPtr.asFunction<void Function()>();


  int InitComplete() {
    return _InitComplete();
  }

  late final _InitCompletePtr =
  _lookup<ffi.NativeFunction<ffi.Uint8 Function()>>('InitComplete');
  late final _InitComplete = _InitCompletePtr.asFunction<int Function()>();

  Prove_return ProveChaCha(
    GoSlice counter,
    GoSlice key,
    GoSlice nonce,
    GoSlice plaintext
  ) {
    return _ProveChaCha(
      counter,
      key,
      nonce,
      plaintext
    );
  }

  late final _ProvePtrChaCha = _lookup<
      ffi.NativeFunction<
          Prove_return Function(
              GoSlice, GoSlice, GoSlice, GoSlice)>>('ProveChaCha');
  late final _ProveChaCha = _ProvePtrChaCha.asFunction<
      Prove_return Function(GoSlice, GoSlice, GoSlice, GoSlice)>();


  Prove_return ProveAES128(
      GoSlice counter,
      GoSlice key,
      GoSlice nonce,
      GoSlice plaintext,
      ) {
    return _ProveAES128(
      counter,
      key,
      nonce,
      plaintext,
    );
  }

  late final _ProveAES128Ptr = _lookup<
      ffi.NativeFunction<
          Prove_return Function(
              GoSlice, GoSlice, GoSlice, GoSlice)>>('ProveAES128');
  late final _ProveAES128 = _ProveAES128Ptr.asFunction<
      Prove_return Function(GoSlice, GoSlice, GoSlice, GoSlice)>();


  Prove_return ProveAES256(
      GoSlice counter,
      GoSlice key,
      GoSlice nonce,
      GoSlice plaintext
      ) {
    return _ProveAES256(
      counter,
      key,
      nonce,
      plaintext
    );
  }

  late final _ProveAES256Ptr = _lookup<
      ffi.NativeFunction<
          Prove_return Function(
              GoSlice, GoSlice, GoSlice, GoSlice)>>('ProveAES256');
  late final _ProveAES256 = _ProveAES256Ptr.asFunction<
      Prove_return Function(GoSlice, GoSlice, GoSlice, GoSlice)>();
  
}

final class GoSlice extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> data;

  @GoInt()
  external int len;

  @GoInt()
  external int cap;
}

typedef GoInt = GoInt64;
typedef GoInt64 = ffi.LongLong;
typedef DartGoInt64 = int;

final class Prove_return extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> r0;

  @GoInt()
  external int r1;
}
