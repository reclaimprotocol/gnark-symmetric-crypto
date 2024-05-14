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

  Prove_return Prove(
    GoSlice key,
    GoSlice nonce,
    int cnt,
    GoSlice plaintext,
    GoSlice ciphertext,
  ) {
    return _Prove(
      key,
      nonce,
      cnt,
      plaintext,
      ciphertext,
    );
  }

  late final _ProvePtr = _lookup<
      ffi.NativeFunction<
          Prove_return Function(
              GoSlice, GoSlice, ffi.Int, GoSlice, GoSlice)>>('Prove');
  late final _Prove = _ProvePtr.asFunction<
      Prove_return Function(GoSlice, GoSlice, int, GoSlice, GoSlice)>();
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
