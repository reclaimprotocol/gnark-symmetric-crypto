/* Code generated by cmd/cgo; DO NOT EDIT. */

/* package command-line-arguments */

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef size_t GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;

typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif

extern void Free(void* pointer);
extern void Init();

/* Return type for Prove */
struct Prove_return {
	void* r0;
	GoInt r1;
};
extern struct Prove_return Prove(GoSlice key, GoSlice nonce, int cnt, GoSlice plaintext, GoSlice ciphertext);

#ifdef __cplusplus
}
#endif
