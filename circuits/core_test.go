package circuits

import (
	"crypto/rand"
	"encoding/json"
	"gnark-symmetric-crypto/utils"
	"gnark-symmetric-crypto/verifier"
	"math"
	"math/big"
	"sync"
	"testing"
	"unsafe"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestProveVerify(t *testing.T) {
	assert := test.NewAssert(t)
	wg := new(sync.WaitGroup)
	wg.Add(3)
	go func() {
		params := `{"cipher":"chacha20","key":[[0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"nonce":[[0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"input":[[1,0,0,1,1,0,0,1,0,1,0,0,1,0,0,0,1,1,0,0,0,0,1,0,0,0,1,0,0,0,0,1],[1,1,1,0,1,0,1,1,1,0,0,1,0,0,1,0,1,1,1,1,0,1,0,0,0,1,0,1,1,0,1,1],[1,1,1,0,0,0,1,1,0,0,0,0,0,0,1,1,0,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1],[0,1,1,1,1,0,1,1,0,0,1,0,1,1,0,0,0,0,0,0,1,0,1,1,0,1,0,1,0,1,0,1],[0,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0,0,0,1,1,1,0,0,1,1,1,1,0,0,0,1,1],[0,0,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,0,1,0,0,0],[0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[0,0,1,0,1,0,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0],[1,1,0,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0],[1,0,0,1,0,1,0,0,0,1,0,1,0,0,1,0,0,1,0,0,0,1,1,1,0,1,0,1,1,1,1,1],[0,1,0,0,0,1,1,1,0,1,1,0,1,1,1,0,0,0,1,0,1,0,1,1,1,1,0,0,0,0,1,1],[1,0,0,0,1,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,0,0,1,1,0,1,1,1,0,1],[0,1,1,1,1,0,0,1,1,1,0,0,0,1,1,0,1,1,1,0,0,1,0,0,1,0,0,1,1,1,1,1],[0,0,1,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,1,0,1,1,1,0,0,1,1],[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]}`
		_, resLen := Prove([]byte(params))
		assert.True(resLen > 0)
		wg.Done()
	}()

	go func() {
		params := `{"cipher":"aes-128-ctr","key":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"nonce":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0],"input":[0,0,1,1,1,0,1,1,0,0,1,0,1,1,1,1,0,1,0,0,0,0,0,1,0,1,0,0,1,0,0,0,0,1,1,1,0,0,0,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,0,0,0,0,0,1,0,1,1,1,1,0,0,0,0,0,1,1,1,1,1,0,1,1,1,1,1,0,1,0,0,1,0,0,0,1,0,0,1,1,0,1,0,0,1,1,0,1,1,0,0,0,0,0,1,1,0,1,1,0,1,1,0,1,1,0,1,0,0,1,0,0,0,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,1,0,1,1,1,0,0,0,0,0,1,0,1,1,0,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,0,1,1,0,0,1,0,0,1,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,1,0,0,1,1,1,1,0,0,0,1,1,1,0,1,1,1,1,0,1,1,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,1,0,0,0,1,0,0,0,0,1,0,0,1,0,0,1,0,0,0,1,0,1,1,0,0,0,0,0,0,0,0,1,0,1,0,0,1,1,0,1,0,0,1,1,0,1,0,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,0,1,0,1,1,0,1,0,0,1,1,1,0,1,0,0,1,1,0,0,0,0,0,1,0,1,0,0,0,1,1,1,1,1,1,1,1,1,1,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,0,0,1,1,0,1,1,0,0,1,1,1,1,0,0,1,0,0,1,0,1,1,1,1,0,1,1,1,0,1,0,1,1,0,1,1,1,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
		_, resLen := Prove([]byte(params))
		assert.True(resLen > 0)
		wg.Done()
	}()

	go func() {
		params := `{"cipher":"aes-256-ctr","key":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"nonce":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0],"input":[0,0,1,0,1,1,0,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0,1,1,1,1,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,1,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,0,1,0,1,0,0,0,1,0,1,1,0,0,1,1,0,0,0,1,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,0,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,1,0,1,0,0,1,0,0,0,0,0,1,1,1,0,0,1,1,1,0,0,0,0,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1,0,1,0,1,1,0,1,0,0,1,0,1,0,0,1,0,1,1,0,1,0,1,0,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,1,1,1,1,0,1,0,1,1,0,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,1,1,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,0,0,1,1,1,0,0,1,0,0,1,0,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
		_, resLen := Prove([]byte(params))
		assert.True(resLen > 0)
		wg.Done()
	}()

	wg.Wait()
	assert.True(verifier.Verify([]byte(`{"cipher":"chacha20","proof":"a265154412ba0e83245a5e3eaa61a0e4152f13d1823039a20fac988fb7b5769aa143b77f7f6ef0d41600955865a112fca6bbed29c9c4db3eeec264378679db882b18bb8c190194b875384c4842c7739109353b9101d0ea3f05f93fa12aea856b854e0e543977029f74086b21139032f513671ca6cbdce86bbb58ddb67b08cbc0000000004000000000000000000000000000000000000000000000000000000000000000","publicSignals":[0,1,1,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,1,1,0,0,1,0,1,0,0,1,1,0,1,0,0,1,0,0,0,0,0,0,1,1,0,1,1,0,0,0,1,1,0,1,1,1,1,0,1,1,0,1,1,1,1,0,0,1,0,0,0,0,0,0,1,0,0,1,0,0,1,0,1,0,1,0,0,0,0,0,1,0,0,0,0,0,1,0,1,1,1,0,0,1,0,0,1,1,0,0,0,1,1,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1,0,1,1,0,1,0,0,1,0,0,1,0,0,0,0,0,0,1,1,1,0,1,0,0,0,1,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,0,0,0,1,1,1,0,0,1,1,0,0,1,1,0,1,1,0,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,1,0,1,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,0,0,0,1,1,0,0,0,1,0,0,0,1,1,0,0,1,0,0,0,1,0,1,1,1,0,0,0,0,1,0,0,1,1,0,1,0,0,0,1,1,1,1,0,0,0,0,1,1,0,1,1,0,0,0,1,0,1,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,1,1,1,0,0,1,1,0,0,1,0,1,0,1,1,1,0,0,1,1,0,1,1,0,0,0,0,1,0,1,1,0,0,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,1,1,0,1,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,0,0,0,1,1,1,0,1,0,0,0,0,1,0,0,1,1,1,0,1,1,0,0,0,0,1,0,1,1,0,0,1,0,1,0,1,1,1,0,1,1,0,0,1,1,0,0,1,0,1,0,1,1,1,0,1,0,0,0,1,1,0,1,0,0,1,0,0,1,0,0,0,0,0,0,1,1,0,1,1,0,0,1,0,1,1,1,1,1,0,1,1,1,1,1,0,1,1,0,0,0,0,0,0,1,1,1,0,1,1,1,0,0,1,1,0,0,1,1,0,0,1,0,1,0,0,1,0,0,0,1,1,0,0,0,0,1,0,0,0,1,0,0,0,0,1,1,1,1,0,1,0,1,1,1,0,0,1,0,0,1,0,1,1,1,1,0,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,0,0,1,1,0,0,0,0,0,0,1,1,0,1,0,1,0,0,1,1,1,1,0,1,0,1,0,1,0,1,1,1,1,0,1,1,0,0,1,0,1,1,0,0,0,0,0,0,1,0,1,1,0,1,0,1,0,1,0,1,0,0,0,0,1,1,1,1,1,1,1,1,1,0,0,0,0,0,1,1,1,0,0,1,1,1,1,0,0,0,1,1,0,0,1,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,1,1,0,0,1,1,0,1,1,0,1,0,0,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,1,1,0,1,1,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,0,0,1,0,1,0,0,0,1,0,1,0,0,1,0,0,1,0,0,0,1,1,1,0,1,0,1,1,1,1,1,0,1,0,0,0,1,1,1,0,1,1,0,1,1,1,0,0,0,1,0,1,0,1,1,1,1,0,0,0,0,1,1,1,0,0,0,1,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,0,0,1,1,0,1,1,1,0,1,0,1,1,1,1,0,0,1,1,1,0,0,0,1,1,0,1,1,1,0,0,1,0,0,1,0,0,1,1,1,1,1,0,0,1,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,0,0,0,1,1,0,1,1,1,0,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`)))
	assert.True(verifier.Verify([]byte(`{"cipher":"aes-128-ctr","proof":"5b2279547630594e425552447a58466e5946444f307872704f73734f655563694558714237584e2b7149424637424c4c6747533238642b616f6f4139714d456778754a7171676b71314772617a664844696147306d617253676e636252497a684166616d7a77566f7568367030373445674e69782f496356547a6243304d42666530724d57726e50455358694b4f325164526570454f757a71655158754a71346c353555346d303763664353344141414141514141414141414141414141414141414141414141414141414141414141414141414141414141414141413d222c226e5674564d44684f4d42502f364f396d6d52626635535a2f6155543254427358342f2b324255326a4836377376594d685830756b7442364d6d6278374b4c50534e6f51554136727756614561664b77436c674e7a4a4250646b3050325950567141786758516235443842462f59384d54795774674675654c6e53614570693253727458545a2b73504c725170464b336879332f4b6d30736c636d506a58346f6450784a364c6576703572304141414141514141414141414141414141414141414141414141414141414141414141414141414141414141414141413d222c226975784d5a626242356959516a693343412b744f4d4a7068665775327854393741437a4b79574d536e58727077576f6e4645356c694461425566355a774d7143544a41526a77376a35434b6335435a6f667a46586442314c786570324b4468784d546b537436443950717937626545523062356d4c416d5963335141705838523061573531386b473949516b72502f75444b714e70303537446743355974665673433977566c49473339414141414141514141414141414141414141414141414141414141414141414141414141414141414141414141414141413d222c2267486c6e624d326b787056507275694a6d4f5a735437597a484577336d397956627039502f70794f446a2f4d31446c766f724f777a4c4e5a73535179314261415031694b7547304f5474664668694e5235396a5a4453734e504750325142594c30517150572b3173515876723352394c4c314668714e615a365764477031572b69676f73613762306b5235384b424e6b4142787a2f546e6935497544705839674d7156502f6371644258514141414141514141414141414141414141414141414141414141414141414141414141414141414141414141414141413d225d","publicSignals":[0,1,1,0,1,1,0,0,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,0,0,1,1,0,0,1,0,1,0,1,1,0,1,1,0,1,1,0,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,1,1,0,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,1,0,0,0,1,1,1,0,1,0,0,0,1,1,1,0,1,1,0,1,1,1,1,0,1,0,0,0,0,1,0,1,1,1,1,1,1,1,1,0,1,1,0,1,1,1,1,0,1,1,1,0,0,1,0,0,0,1,0,0,0,0,0,0,1,1,1,0,0,1,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,1,0,1,1,0,1,1,0,1,0,1,1,0,0,1,0,1,0,1,1,1,0,1,0,0,0,0,1,0,1,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,1,1,0,1,1,0,1,1,1,1,0,1,1,0,1,1,1,0,0,1,1,1,0,0,1,1,0,1,1,0,0,1,0,1,0,1,1,0,0,0,1,1,0,1,1,1,0,1,0,0,0,1,1,0,0,1,0,1,0,1,1,1,0,1,0,0,0,1,1,1,0,1,0,1,0,1,1,1,0,0,1,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,1,0,1,1,0,0,1,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,0,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,0,1,1,0,1,1,0,0,0,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,1,1,0,0,1,1,0,0,1,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,1,0,1,1,0,1,1,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,1,0,0,0,0,1,0,1,1,0,0,0,0,0,0,1,0,1,0,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,1,0,1,1,1,0,0,1,1,0,1,1,0,0,1,0,1,0,1,1,0,0,1,0,0,0,0,0,1,1,0,1,0,0,0,1,1,1,0,0,1,0,0,0,1,0,0,1,1,0,1,0,0,1,1,1,0,0,1,1,1,0,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,1,0,0,0,1,1,0,1,0,1,0,0,1,0,1,1,1,1,1,0,1,0,1,0,1,0,1,1,0,0,1,1,1,0,1,1,0,0,1,0,1,0,0,1,0,1,1,0,0,1,0,0,1,1,0,1,1,1,0,1,0,0,0,0,0,0,0,0,1,0,1,1,1,0,1,1,0,0,1,1,0,0,1,1,1,0,1,1,1,0,1,1,1,0,0,1,1,1,1,0,0,0,0,1,0,1,1,1,0,0,0,1,1,0,1,1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,0,1,1,1,0,1,0,0,0,1,1,0,0,1,1,0,1,1,1,0,1,1,0,0,0,0,0,1,0,0,0,0,0,1,1,1,0,1,0,1,1,1,0,0,1,1,1,1,0,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,1,1,0,0,1,0,0,0,1,0,0,0,1,0,1,0,1,1,1,1,0,1,1,1,1,1,0,0,0,1,1,0,1,0,0,1,0,0,0,1,1,0,0,0,1,0,0,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,0,1,0,1,0,0,0,0,0,1,0,1,0,0,1,1,0,0,0,1,1,1,1,0,1,1,1,0,1,0,0,1,1,1,1,0,0,1,1,1,0,0,0,1,1,1,1,1,1,1,0,1,0,1,0,1,1,1,1,0,1,0,1,0,0,1,0,1,1,0,0,1,1,0,1,1,0,1,1,1,1,1,0,0,1,1,0,0,1,0,1,0,0,1,1,1,0,0,0,1,0,1,0,0,1,0,0,0,1,0,1,0,1,0,1]}`)))
	assert.True(verifier.Verify([]byte(`{"cipher":"aes-256-ctr","proof":"5b226d6352514a364b6275654c6e68495431374c30303974336c3644354d6a6734527a57726d3063707671476e5664523532737270353775762f63545576475a594f6533355a6a432b5457644565367a4f362f4e70394a43612f6f68646975737731694341506675646159614b724f554c754e4b437132393069327638456b664a536a67566565477a7679646d4b577435646d6539756c446b704c704662725359357259614c4d7544545961454141414141514141414141414141414141414141414141414141414141414141414141414141414141414141414141413d222c226c7457516a51756e424f644433683345702b50796655556e52576c585074764a2b66674c37683074757576616931786b4d4679694b7955484a573949397734774575464477426c746f33356f346c2b73737a4d57467846426a313037676365466e63576f4265424e2b574652744455344856477357616a4669636c7a3064734b334a3347464c6d6e394476496c7257384470664c72716344714b63614d367546394961593971454e5a2f6b4141414141514141414141414141414141414141414141414141414141414141414141414141414141414141414141413d222c22676c38655953774b3151697758714d4a7456363573553062387655476a63723250702f3572664650612b6a7563583049625a7438375437452b636e464f38715048792b4354496e48395578735a393178783356644c524b717832412b514a454e7649634b7a726f5149533663674c6250444c4c482b3073504b58754a4f7671437941385142704468535743695834337761764d78636e77432f4b594b6d493135393041536569452f2f66414141414141514141414141414141414141414141414141414141414141414141414141414141414141414141414141413d222c22324175575a697a6c576f61715a766549304378552b53676b2f63514832497a2f6e6c613834364936636c44717245326d2b7874556b357262645a733448776d4374687a45737274494133586c6e387338584d776d584336393749322f5431463367734c4b582f6a6c4b5274616c33693748704933346c535468303351637064436766792f635858626d4d4b4d727433723363707730365765506f4879327a617641574f723668482b6251494141414141514141414141414141414141414141414141414141414141414141414141414141414141414141414141413d225d","publicSignals":[0,1,0,0,1,1,0,1,0,1,1,1,1,0,0,1,0,0,1,0,0,0,0,0,0,1,1,0,0,0,1,1,0,1,1,0,1,1,1,1,0,1,1,0,1,1,1,1,0,1,1,0,1,1,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0,0,0,1,0,1,0,1,0,0,0,0,0,1,0,0,1,0,0,1,0,0,1,0,0,0,0,0,0,1,1,1,0,0,1,1,0,1,1,0,0,1,0,1,0,1,1,0,0,0,1,1,0,1,1,1,0,0,1,0,0,1,1,0,0,1,0,1,0,1,1,1,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,0,1,1,0,0,1,0,0,0,0,0,0,0,1,0,0,0,1,0,0,1,1,1,0,0,0,1,0,1,1,1,0,1,1,0,1,1,1,1,1,1,1,1,1,0,0,0,0,1,1,1,1,1,0,1,0,0,1,0,1,0,0,0,0,0,1,1,0,1,1,0,1,1,1,1,0,0,0,1,0,1,1,1,0,0,1,1,0,1,0,0,1,1,1,0,1,0,0,1,1,1,0,1,0,0,1,1,0,0,1,1,0,1,1,0,0,0,1,0,0,0,1,0,0,0,1,0,1,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,0,0,0,0,0,1,1,0,1,1,0,0,0,1,1,0,0,1,0,1,0,1,1,0,0,0,0,1,0,1,1,1,0,0,1,1,0,1,1,0,0,1,0,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,1,1,0,1,1,1,1,0,1,1,0,1,1,1,0,0,0,1,0,0,1,1,1,0,1,1,1,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,1,0,0,1,0,0,1,1,0,0,1,0,1,0,1,1,1,0,1,1,0,0,1,1,0,0,1,0,1,0,1,1,0,0,0,0,1,0,1,1,0,1,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,1,1,1,0,1,0,0,1,1,1,1,0,1,1,0,1,1,1,0,1,0,1,0,0,1,1,1,0,0,1,1,0,0,1,1,0,1,1,1,0,0,1,0,1,1,0,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0,1,1,1,1,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,1,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,0,1,0,1,0,0,0,1,0,1,1,0,0,1,1,0,0,0,1,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,0,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,1,0,1,0,0,1,0,0,0,0,0,1,1,1,0,0,1,1,1,0,0,0,0,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1,0,1,0,1,1,0,1,0,0,1,0,1,0,0,1,0,1,1,0,1,0,1,0,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,1,1,1,1,0,1,0,1,1,0,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,1,1,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,0,0,1,1,1,0,0,1,0,0,1,0,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`)))

}

func TestPanic(t *testing.T) {
	assert := test.NewAssert(t)
	params := `{"cipher":"aes-256-ctr1","key":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"nonce":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0],"input":[0,0,1,0,1,1,0,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0,1,1,1,1,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,1,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,0,1,0,1,0,0,0,1,0,1,1,0,0,1,1,0,0,0,1,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,0,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,1,0,1,0,0,1,0,0,0,0,0,1,1,1,0,0,1,1,1,0,0,0,0,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1,0,1,0,1,1,0,1,0,0,1,0,1,0,0,1,0,1,1,0,1,0,1,0,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,1,1,1,1,0,1,0,1,1,0,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,1,1,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,0,0,1,1,1,0,0,1,0,0,1,0,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	_, resLen := Prove([]byte(params))
	assert.True(resLen > 2)

	assert.False(verifier.Verify([]byte(`{"cipher":"chacha20"}`)))
}

func TestFullChaCha20(t *testing.T) {
	assert := test.NewAssert(t)
	bKey := make([]byte, 32)
	bNonce := make([]byte, 12)

	bPt := make([]byte, 64)

	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bPt)

	key := utils.UintsToBits(utils.BytesToUint32LERaw(bKey))
	nonce := utils.UintsToBits(utils.BytesToUint32LERaw(bNonce))
	cnt := utils.Uint32ToBitsLE(counter)

	plaintext := utils.UintsToBits(utils.BytesToUint32BERaw(bPt))

	pt := make([]uint8, len(plaintext)*32)
	for i := 0; i < len(plaintext); i++ {
		for j := 0; j < 32; j++ {
			pt[i*32+j] = uint8(plaintext[i][j].(uint))
		}
	}

	inputParams := struct {
		Cipher  string                  `json:"cipher"`
		Key     [][32]frontend.Variable `json:"key"`
		Nonce   [][32]frontend.Variable `json:"nonce"`
		Counter [32]frontend.Variable   `json:"counter"`
		Input   [][32]frontend.Variable `json:"input"`
	}{
		Cipher:  "chacha20",
		Key:     key,
		Nonce:   nonce,
		Counter: cnt,
		Input:   plaintext,
	}

	buf, _ := json.Marshal(inputParams)

	res, resLen := Prove(buf)
	assert.True(resLen > 0)
	resBuf := unsafe.Slice((*byte)(res), resLen)
	var outParams *OutputParams
	json.Unmarshal(resBuf, &outParams)

	inParams := &verifier.InputVerifyParams{
		Cipher:        "chacha20",
		Proof:         outParams.Proof.ProofJson,
		PublicSignals: append(toUint8(outParams.PublicSignals), pt...),
	}
	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

func toUint8(a []int) []uint8 {
	res := make([]uint8, len(a))
	for i, v := range a {
		res[i] = uint8(v)
	}
	return res
}
