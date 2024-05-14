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
      title: 'Flutter Demo',
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
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
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
  void _incrementCounter() {
    setState(() {
      // This call to setState tells the Flutter framework that something has
      // changed in this State, which causes it to rerun the build method below
      // so that the display can reflect the updated values. If we changed
      // _counter without calling setState(), then the build method would not be
      // called again, and so nothing would appear to happen.
      _counter++;
      final key = hexToGoSlice('D9C2B1A3CC33A5E2BB2687743747474238AE2EACD2732E2AAD793769B3E42BAE');
      final nonce = hexToGoSlice('CF3F95A5033F258FE329C9E4');
      final plaintext = hexToGoSlice('EA2D019860FA70BC851D859BBF7C4CD7BB6684B0E4D1E820F481DD8B1EE7449E03AE65DD401FB9D61F74CD1A12C9449AFB56FE57D3CC6B891F7C9572CDD1C808');
      final ciphertext = hexToGoSlice('EC05114D08BD31DBB4EF538FC713B8A6206482FCB81891276A74B76D2273AC4B7BF193F3DA1B7125735F06A88AF0B73832EB97F3E1FE0286D4D852B860B97AA4');

      final proof = prover.Prove(key.ref, nonce.ref, 1, plaintext.ref, ciphertext.ref);
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
      _proof = proofStr;
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
            const Text(
              'You have pushed the button this many times:',
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            const Text(
              'Proof:',
            ),
            Text(
              _proof,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: const Icon(Icons.add),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}
