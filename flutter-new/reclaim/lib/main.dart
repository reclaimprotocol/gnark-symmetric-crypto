import 'package:ffi/ffi.dart';
import 'package:flutter/material.dart';
import 'package:hex/hex.dart';
import 'dart:ffi';
import 'libprove.dart' as gnark;


typedef GoInt = GoInt64;
typedef GoInt64 = LongLong;
typedef DartGoInt64 = int;

final dylib = DynamicLibrary.open('libprove.so');
final prover = gnark.NativeLibrary(dylib);

final key = hexToGoSlice('D9C2B1A3CC33A5E2BB2687743747474238AE2EACD2732E2AAD793769B3E42BAE');
final nonce = hexToGoSlice('CF3F95A5033F258FE329C9E4');
final plaintext = hexToGoSlice('EA2D019860FA70BC851D859BBF7C4CD7BB6684B0E4D1E820F481DD8B1EE7449E03AE65DD401FB9D61F74CD1A12C9449AFB56FE57D3CC6B891F7C9572CDD1C808');
final ciphertext = hexToGoSlice('EC05114D08BD31DBB4EF538FC713B8A6206482FCB81891276A74B76D2273AC4B7BF193F3DA1B7125735F06A88AF0B73832EB97F3E1FE0286D4D852B860B97AA4');

void main() {
  runApp(const MyApp());
}

Pointer<gnark.GoSlice> hexToGoSlice(String hex) {
  final bytes = HEX.decode(hex);
  final Pointer<gnark.GoSlice> slice = calloc<gnark.GoSlice>();
  slice.ref.data = calloc<Uint8>(bytes.length);
  slice.ref.data.asTypedList(bytes.length).setRange(0, bytes.length, bytes);
  slice.ref.len = bytes.length;
  slice.ref.cap = bytes.length;
  return slice;
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    prover.Init();
    return MaterialApp(
      title: 'Android Gnark Demo',
      theme: ThemeData(
        // This is the theme of your application.
        //
        // TRY THIS: Try running your application with "flutter run". You'll see
        // the application has a purple toolbar. Then, without quitting the app,
        // try changing the seedColor in the colorScheme below to Colors.green
        // and then invoke "hot reload" (save your changes or press the "hot
        // reload" button in a Flutter-supported IDE, or press "r" if you used
        // the command line to start the app).
        //
        // Notice that the counter didn't reset back to zero; the application
        // state is not lost during the reload. To reset the state, use hot
        // restart instead.
        //
        // This works for code too, not just values: Most code changes can be
        // tested with just a hot reload.
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.green),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'ChaCha20 Gnark Flutter Demo'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;
  String _proof = '';
  String _took = '';
  void _incrementCounter() {
    setState(() {
      // This call to setState tells the Flutter framework that something has
      // changed in this State, which causes it to rerun the build method below
      // so that the display can reflect the updated values. If we changed
      // _counter without calling setState(), then the build method would not be
      // called again, and so nothing would appear to happen.
      if (prover.InitComplete() != 1){
        _proof = 'waiting for init';
        return;
      }
      _counter++;
      var now = DateTime.timestamp();
      final key = hexToGoSlice('D9C2B1A3CC33A5E2BB2687743747474238AE2EACD2732E2AAD793769B3E42BAE');
      final nonce = hexToGoSlice('CF3F95A5033F258FE329C9E4');
      final plaintext = hexToGoSlice('EA2D019860FA70BC851D859BBF7C4CD7BB6684B0E4D1E820F481DD8B1EE7449E03AE65DD401FB9D61F74CD1A12C9449AFB56FE57D3CC6B891F7C9572CDD1C808');
      final ciphertext = hexToGoSlice('EC05114D08BD31DBB4EF538FC713B8A6206482FCB81891276A74B76D2273AC4B7BF193F3DA1B7125735F06A88AF0B73832EB97F3E1FE0286D4D852B860B97AA4');
      final counter = hexToGoSlice('00000001');

      final proof = prover.ProveChaCha(counter.ref, key.ref, nonce.ref, plaintext.ref, ciphertext.ref);
      final proofStr = HEX.encode(proof.r0.asTypedList(proof.r1));
      prover.Free(proof.r0);
      calloc.free(key.ref.data);
      calloc.free(key);
      calloc.free(nonce.ref.data);
      calloc.free(nonce);
      calloc.free(plaintext.ref.data);
      calloc.free(plaintext);
      calloc.free(ciphertext.ref.data);
      calloc.free(ciphertext);
      calloc.free(counter.ref.data);
      calloc.free(counter);
      _proof = proofStr;
      _took = 'Took: ${DateTime.timestamp().difference(now).inMilliseconds} ms';
      /*now = DateTime.timestamp();
      final keyAES128 = hexToGoSlice('7E24067817FAE0D743D6CE1F32539163');
      final nonceAES128  = hexToGoSlice('006CB6DBC0543B59DA48D90B');
      final plaintextAES128  =  hexToGoSlice('000102030405060708090A0B0C0D0E0F');
      final ciphertextAES128  = hexToGoSlice('5104A106168A72D9790D41EE8EDAD388');
      final counterAES128 = hexToGoSlice('00000001');

      final proofAES128  = prover.ProveAES128(counterAES128.ref, keyAES128.ref, nonceAES128.ref, plaintextAES128.ref, ciphertextAES128.ref);
      final proofStrAES128  = HEX.encode(proofAES128.r0.asTypedList(proofAES128.r1));
      prover.Free(proofAES128.r0);
      calloc.free(keyAES128.ref.data);
      calloc.free(keyAES128);
      calloc.free(nonceAES128.ref.data);
      calloc.free(nonceAES128);
      calloc.free(plaintextAES128.ref.data);
      calloc.free(plaintextAES128);
      calloc.free(ciphertextAES128.ref.data);
      calloc.free(ciphertextAES128);
      calloc.free(counterAES128.ref.data);
      calloc.free(counterAES128);
      _proof = '$_proof\n\nAES128: $proofStrAES128';
      _proof = '$_proof\n\nTook: ${DateTime.timestamp().difference(now).inMilliseconds} ms';

      now = DateTime.timestamp();
      final keyAES256 = hexToGoSlice('F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884');
      final nonceAES256  = hexToGoSlice('00FAAC24C1585EF15A43D875');
      final plaintextAES256  =  hexToGoSlice('000102030405060708090A0B0C0D0E0F');
      final ciphertextAES256  = hexToGoSlice('F05E231B3894612C49EE000B804EB2A9');
      final counterAES256 = hexToGoSlice('00000001');

      final proofAES256  = prover.ProveAES256(counterAES256.ref, keyAES256.ref, nonceAES256.ref, plaintextAES256.ref, ciphertextAES256.ref);
      final proofStrAES256  = HEX.encode(proofAES256.r0.asTypedList(proofAES256.r1));
      prover.Free(proofAES256.r0);
      calloc.free(keyAES256.ref.data);
      calloc.free(keyAES256);
      calloc.free(nonceAES256.ref.data);
      calloc.free(nonceAES256);
      calloc.free(plaintextAES256.ref.data);
      calloc.free(plaintextAES256);
      calloc.free(ciphertextAES256.ref.data);
      calloc.free(ciphertextAES256);
      calloc.free(counterAES256.ref.data);
      calloc.free(counterAES256);
      _proof = '$_proof\n\nAES256: $proofStrAES256';
      _proof = '$_proof\n\nTook: ${DateTime.timestamp().difference(now).inMilliseconds} ms';*/
    });
  }

  @override
  Widget build(BuildContext context) {
    // This method is rerun every time setState is called, for instance as done
    // by the _incrementCounter method above.
    //
    // The Flutter framework has been optimized to make rerunning build methods
    // fast, so that you can just rebuild anything that needs updating rather
    // than having to individually change instances of widgets.
    return Scaffold(
      appBar: AppBar(
        // TRY THIS: Try changing the color here to a specific color (to
        // Colors.amber, perhaps?) and trigger a hot reload to see the AppBar
        // change color while the other colors stay the same.
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        // Here we take the value from the MyHomePage object that was created by
        // the App.build method, and use it to set our appbar title.
        title: Text(widget.title),
      ),
      body: Center(
        // Center is a layout widget. It takes a single child and positions it
        // in the middle of the parent.
        child: Column(
          // Column is also a layout widget. It takes a list of children and
          // arranges them vertically. By default, it sizes itself to fit its
          // children horizontally, and tries to be as tall as its parent.
          //
          // Column has various properties to control how it sizes itself and
          // how it positions its children. Here we use mainAxisAlignment to
          // center the children vertically; the main axis here is the vertical
          // axis because Columns are vertical (the cross axis would be
          // horizontal).
          //
          // TRY THIS: Invoke "debug painting" (choose the "Toggle Debug Paint"
          // action in the IDE, or press "p" in the console), to see the
          // wireframe for each widget.
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Text(
              'You generated proof this many times:',
                style: Theme.of(context).textTheme.headlineSmall,
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headlineLarge,
            ),
            Text(
              'Proof of 1 ChaCha20 block:',
                style: Theme.of(context).textTheme.headlineMedium
            ),
            Text(
              _proof,
              style: Theme.of(context).textTheme.bodyLarge,
            ),
            Text(
              _took,
              style: Theme.of(context).textTheme.headlineMedium,
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: const Icon(Icons.generating_tokens),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}
