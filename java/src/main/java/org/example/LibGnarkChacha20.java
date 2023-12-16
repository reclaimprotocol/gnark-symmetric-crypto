package org.example;

import com.sun.jna.*;

import java.util.Arrays;
import java.util.List;

public interface LibGnarkChacha20 extends Library {
    class GoSlice extends Structure {
        public static class ByValue extends GoSlice implements Structure.ByValue {
            public ByValue(byte[] b)  {
                Pointer pData = new Memory(b.length);
                pData.write(0, b, 0, b.length);

                this.data = pData;
                this.len = b.length;
                this.cap = this.len;
            }
        }
        public static class ReturnSlice extends Structure {
            public static class ByValue extends ReturnSlice implements Structure.ByValue {}
            public Pointer r0;
            public long r1;
            protected List<String> getFieldOrder() {
                return Arrays.asList(new String[]{"r0", "r1"});
            }
        }
        public Pointer data;
        public long len;
        public long cap;
        protected List<String> getFieldOrder(){
            return Arrays.asList(new String[]{"data","len","cap"});
        }
    }
    // Prove function itself
    GoSlice.ReturnSlice.ByValue Prove(GoSlice.ByValue key, GoSlice.ByValue nonce, int cnt, GoSlice.ByValue plaintext, GoSlice.ByValue ciphertext);
    //Call after each Prove call!!!
    void Free(Pointer p);
}

