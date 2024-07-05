import 'dart:convert';

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
      final params = hexToGoSlice('7b22636970686572223a226165732d3132382d637472222c226b6579223a223435386263336235636431663438326132336166656363313738633839396263222c226e6f6e6365223a22653739353030373234373963316161666638323733623361222c22636f756e746572223a312c22696e707574223a226436323966326461613437373662643362303031303165383232376466633963227d');


      final proof = prover.Prove(params.ref);
      final proofStr = String.fromCharCodes(proof.r0.asTypedList(proof.r1));
      final output = jsonDecode(proofStr) as Map<String, dynamic>;
      prover.Free(proof.r0);
      calloc.free(params.ref.data);
      calloc.free(params);
      _proof = output['output']!;
      _proof = '$_proof\nTook: ${DateTime.timestamp().difference(now).inMilliseconds} ms';
     /*now = DateTime.timestamp();
      final keyAES128 = hexToGoSlice('7E24067817FAE0D743D6CE1F32539163');
      final nonceAES128  = hexToGoSlice('006CB6DBC0543B59DA48D90B');
      final plaintextAES128  =  hexToGoSlice('000102030405060708090A0B0C0D0E0F');
      final counterAES128 = hexToGoSlice('00000001');

      final proofAES128  = prover.ProveAES128(counterAES128.ref, keyAES128.ref, nonceAES128.ref, plaintextAES128.ref);
      final proofStrAES128  = HEX.encode(proofAES128.r0.asTypedList(proofAES128.r1));
      prover.Free(proofAES128.r0);
      calloc.free(keyAES128.ref.data);
      calloc.free(keyAES128);
      calloc.free(nonceAES128.ref.data);
      calloc.free(nonceAES128);
      calloc.free(plaintextAES128.ref.data);
      calloc.free(plaintextAES128);
      calloc.free(counterAES128.ref.data);
      calloc.free(counterAES128);
      _proof = '$_proof\n\nAES128: $proofStrAES128';
      _proof = '$_proof\n\nTook: ${DateTime.timestamp().difference(now).inMilliseconds} ms';

      now = DateTime.timestamp();
      final keyAES256 = hexToGoSlice('F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884');
      final nonceAES256  = hexToGoSlice('00FAAC24C1585EF15A43D875');
      final plaintextAES256  =  hexToGoSlice('000102030405060708090A0B0C0D0E0F');
      final counterAES256 = hexToGoSlice('00000001');

      final proofAES256  = prover.ProveAES256(counterAES256.ref, keyAES256.ref, nonceAES256.ref, plaintextAES256.ref);
      final proofStrAES256  = HEX.encode(proofAES256.r0.asTypedList(proofAES256.r1));
      prover.Free(proofAES256.r0);
      calloc.free(keyAES256.ref.data);
      calloc.free(keyAES256);
      calloc.free(nonceAES256.ref.data);
      calloc.free(nonceAES256);
      calloc.free(plaintextAES256.ref.data);
      calloc.free(plaintextAES256);
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
        child: SingleChildScrollView(
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
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
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
          ],
        )),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: const Icon(Icons.generating_tokens),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}
