# crypto/ASSS write-up

**Challenge name:** crypto/ASSS (CygnusX)

**Description:** 
Welcome to the Amazing SSS! Join now to get your share of the secret. Flag is 66 bytes long.

`ncat --ssl asss.atreides.b01lersc.tf 8443`

**TL;DR**: A flawed Shamir's Secret Sharing (SSS) scheme leaks the flag through modular arithmetic.

## Initial analysis
Upon connecting to the server, we get something like this:
```bash
Here is a ^_^: 15977398395132115717
Here is your share ^_^: (14341609275200113721, 2490790900443170488737684733770025348144803278150430550432981513576385793644846073092041281652196422580730433279120376580370077083082578338894634446685560990988847570802808620785029246231070643829803766708905925233920359088926370741422643831046917247896729733294209405512453100550754708879561484578363409799887124675788842406425733774403474236315906833969872128314932352491385548347498778244604095220248)
```

The description provides a hint that this is some variation on Shamir's Secret Sharing (SSS). We're told the flag is 66 bytes long. We're also provided with the server's source code (annotated below):

```python
from Crypto.Util.number import getPrime, bytes_to_long

def evaluate_poly(poly:list, x:int, s:int):
	# P(x) = s + poly[0]*x^1 + poly[1]*x^2 + ... + poly[18]*x^19
    return s + sum(co*x**(i+1) for i, co in enumerate(poly))

# Load the secret flag as a large integer s
s = bytes_to_long(open("./flag.txt", "rb").read())

# Generate a random 64-bit prime 'a' specific to this connection
a = getPrime(64)

# poly = [a_1, a_2, ..., a_19] where a_i = a * getPrime(64)
# Each coefficient is a multiple of 'a'
poly = [a*getPrime(64) for _ in range(1, 20)]

# Generate a random 64-bit prime 'x' to be the evaluation point for the share
share = getPrime(64)

print(f"Here is a ^_^: {a}")
print(f"Here is your share ^_^: ({share}, {evaluate_poly(poly, share, s)})")
```

From the code, we see that: 
1. The secret `s` is the flag converted to a long integer, and is the constant term of a polynomial.
2. A polynomial $P(x)$ is constructed as $P(x) = s + a_1 x + a_2 x^2 + \cdots + a_{19} x^{19}$.
3. Every coefficient $a_i$ (for $i = 1$ to $19$) is generated as `a * getPrime(64)`, meaning each $a_i$ is a multiple of the 64-bit prime $a$ that is unique to that specific connection instance.
4. The server provides the 64-bit prime $a$, the share $x$, and value of the polynomial at the share $y=P(x)$.

A quick diagram to visualize the polynomial construction:
```
Polynomial P(x) = s + a₁x¹ + a₂x² + ... + a₁₉x¹⁹
                   ↑    ↑       ↑          ↑
                   |    |       |          |
                 flag   a·p₁    a·p₂    a·p₁₉
                   |    |       |          |
                   |    +-------+----------+
                   |            |
                   |      All multiples of a
                   |
             Our target
```

## Using modular arithmetic to exploit the polynomial design
Since each $a_i$ (for $i \ge 1$) is a multiple of the prime `a` given in the same connection, we know that:

$$ a_i \equiv 0 \pmod{a} \quad \text{for } i = 1, 2, \ldots, 19 $$

We are given the value $y = P(x)$, where:

$$ y = s + a_1 x^1 + a_2 x^2 + \cdots + a_{19} x^{19} $$

If we consider this equation modulo the prime `a` provided by the server for that connection, all terms containing $a_i$ become zero:

$$ y \equiv s + (0 \cdot x^1) + (0 \cdot x^2) + \cdots + (0 \cdot x^{19}) \pmod{a} $$

Simplifying this, we get:

$$ y \equiv s \pmod{a} $$

This means that for each connection, the provided pair $(x, y)$ and the prime `a` allow us to determine the remainder of the secret `s` when divided by `a`. 

By connecting to the server multiple times, we can collect several such congruences. Let $(y_j, a_j)$ be the result $y = P(x)$ and the prime modulus $a$ obtained from the $j$-th connection. We get a system of congruences:

$$ s \equiv y_1 \pmod{a_1} $$

$$ s \equiv y_2 \pmod{a_2} $$

$$ \vdots $$

$$ s \equiv y_n \pmod{a_n} $$

Since the $a_j$ values are generated independently as 64-bit primes for each connection, they are overwhelmingly likely to be distinct and therefore pairwise coprime. This is the exact scenario where the Chinese Remainder Theorem (CRT) can be applied to find the value of `s`.

To uniquely determine `s`, the product of the moduli $N = a_1 \cdot a_2 \cdots a_n$ must be greater than `s`. The flag (and thus `s`) is 66 bytes long, which is $66 \times 8 = 528$ bits. So, $s < 2^{528}$. Each modulus $a_j$ is a 64-bit prime, so $a_j \approx 2^{64}$. The product $N \approx (2^{64})^n = 2^{64n}$. We need $N > s$, which means we need $2^{64n} > 2^{528}$. This requires $64n > 528$, or $n > 528 / 64 \approx 8.25$.

Therefore, we must collect data from at least $n = 9$ connections to ensure the product of the moduli is large enough to uniquely determine the 528-bit secret `s`.

So the plan will be:
1. Connect to the server 9 times. In each connection, calculate the remainder.
2. Apply the Chinese Remainder Theorem.
3. Convert the resulting integer `s` back to bytes.

## Implementation
```python
#!/usr/bin/env python3
from pwn import remote
from sympy.ntheory.modular import crt
from Crypto.Util.number import long_to_bytes

HOST, PORT = "asss.atreides.b01lersc.tf", 8443

moduli, remainders, ys = [], [], []

for i in range(9):
    with remote(HOST, PORT, ssl=True) as r:
        # Here is a ^_^: <a>
        a = int(r.recvline().split()[-1])
        # Here is your share ^_^: (x, y)
        share = r.recvline().split(b":")[-1].strip()
        y = int(share.strip(b"()").split(b",")[1])

    moduli.append(a)
    ys.append(y)
    rems = y % a
    remainders.append(rems)

    print(f"a[{i}] = {a}")
    print(f"y[{i}] = {y}")
    print(f"y[{i}] % a[{i}] = {rems}\n")

secret, _ = crt(moduli, remainders)
flag = long_to_bytes(secret, 66).decode()

print(f"Reconstructed s = {secret}")
print(f"Flag = {flag}")
```

```bash
$ python ./crypto_solve_simple.py
[x] Opening connection to asss.atreides.b01lersc.tf on port 8443
[x] Opening connection to asss.atreides.b01lersc.tf on port 8443: Trying 34.57.227.210
[+] Opening connection to asss.atreides.b01lersc.tf on port 8443: Done
[*] Closed connection to asss.atreides.b01lersc.tf port 8443
a[0] = 15805251978533180311
y[0] = 20007419810386375798560913858960052991852239660637533705345429251516061615429691705542796696070404472406309010672108800535920420708615100924171088608241248335812694105597677319892400619500555589736089662261558609566229138032243363652766916676496978031136001725457874012461572186535681210532045271773970470393384870795100845402058010897729236473926522031351352735530010158338921954188420936502637764249312
y[0] % a[0] = 7180928761770669582

[x] Opening connection to asss.atreides.b01lersc.tf on port 8443
[x] Opening connection to asss.atreides.b01lersc.tf on port 8443: Trying 34.57.227.210
[+] Opening connection to asss.atreides.b01lersc.tf on port 8443: Done
[*] Closed connection to asss.atreides.b01lersc.tf port 8443
a[1] = 13201512959133410689
y[1] = 12303907231366822021540229572563182013769615955761121726600494416802625301055435367674055548342158558183601864566593236410222264007200706471476221882287151731786919544506413388791325617418992880620625724623951725370601377868182521945688597433293713155146333402046563818418585485186135593514726042041802588137193171780440659484800175775622443493654385093796071049654780444649287744921442031036966134981604
y[1] % a[1] = 13193928460553174842

[x] Opening connection to asss.atreides.b01lersc.tf on port 8443
[x] Opening connection to asss.atreides.b01lersc.tf on port 8443: Trying 34.57.227.210
[+] Opening connection to asss.atreides.b01lersc.tf on port 8443: Done
[*] Closed connection to asss.atreides.b01lersc.tf port 8443
a[2] = 16409241069811395017
y[2] = 5557053472333797944808108673999301934115298023186566479770124318633939665377352623967161876189090803378046692960549877518952264225902465348549239333322166050285044690387763330323119014583794433745054015661274272586578260627344290946639144414043857762075366745383260208006933502866948996180632335844870059432469192273711640043531038143526882488482856192713734454775780418162630431574531698967835789340156
y[2] % a[2] = 412244038411888550

[x] Opening connection to asss.atreides.b01lersc.tf on port 8443
[x] Opening connection to asss.atreides.b01lersc.tf on port 8443: Trying 34.57.227.210
[+] Opening connection to asss.atreides.b01lersc.tf on port 8443: Done
[*] Closed connection to asss.atreides.b01lersc.tf port 8443
a[3] = 11229916948045556567
y[3] = 849715176241726453465347700287941577033498737399300220345692942199877172973232361435862456433548913407376994144346266056411362887258147055682441326190328942583923777047944862114837045504515308220091554293649123832127154555477153189599334796022178526012225343358731293927672558916983423957944314649897200075778108500798854923434924206635874496139337584387708662211216448775399322088087152446872687272820
y[3] % a[3] = 4871028639549246680

[x] Opening connection to asss.atreides.b01lersc.tf on port 8443
[x] Opening connection to asss.atreides.b01lersc.tf on port 8443: Trying 34.57.227.210
[+] Opening connection to asss.atreides.b01lersc.tf on port 8443: Done
[*] Closed connection to asss.atreides.b01lersc.tf port 8443
a[4] = 9926447921279118883
y[4] = 59839010704897278049056440321813411196949324183498090907381740464531562808448919335537303838993990532355743639597253515122531215141268590058617349694912795255980775990264060969552209526032765107506112740710979601497972190730354470683268249686395779403871857364122408078769325960788434098809687658445189816321091988901650128746336627540823415341326683897500204667269893566116793379504972415092489846428
y[4] % a[4] = 3799743242254489017

[x] Opening connection to asss.atreides.b01lersc.tf on port 8443
[x] Opening connection to asss.atreides.b01lersc.tf on port 8443: Trying 34.57.227.210
[+] Opening connection to asss.atreides.b01lersc.tf on port 8443: Done
[*] Closed connection to asss.atreides.b01lersc.tf port 8443
a[5] = 10610388206545428577
y[5] = 6133849821670305915562152389283394487666781619302975119902520128552595312082219237036578308683627221792459589438277028475891585984062572051727572479703992030587624914789455429101854486544556955985204651210476542960598164375817388446210948966920913574595537230592114188156914107064507180346186855577300288635479356707200581461681761538357904912521525756057529913895071275324028044523026643243809664604
y[5] % a[5] = 6611983146967315258

[x] Opening connection to asss.atreides.b01lersc.tf on port 8443
[x] Opening connection to asss.atreides.b01lersc.tf on port 8443: Trying 34.57.227.210
[+] Opening connection to asss.atreides.b01lersc.tf on port 8443: Done
[*] Closed connection to asss.atreides.b01lersc.tf port 8443
a[6] = 10309448601059825207
y[6] = 44148011890867968388764986657515503889795904947552816903408385152626445521400927861708599001073976725304813783185868516871784248676077066093684539156518984156698353165578679103217802478168577536531897737309510674370049302094058704552553698916859075429791728130400563349952004781674615530389274689572532275247898610260009019872585425392931133699059013534925752302844349942935990253059875718497428869662
y[6] % a[6] = 9335439146091434416

[x] Opening connection to asss.atreides.b01lersc.tf on port 8443
[x] Opening connection to asss.atreides.b01lersc.tf on port 8443: Trying 34.57.227.210
[+] Opening connection to asss.atreides.b01lersc.tf on port 8443: Done
[*] Closed connection to asss.atreides.b01lersc.tf port 8443
a[7] = 10288489071455004611
y[7] = 93691120974965852721827093070555993748695915633556767820178485799402101973005620613427364090268533360806731198766346081621260907150724035495456979684885368337356386978173342941104423149959168149664209470419371523984982064890019237192175570675108067501248911276335430533276870473482015087919612809885049988657616704795317216142833603277400192130346952920711178611351662303017817980945269202181653745766908
y[7] % a[7] = 2206881156256536456

[x] Opening connection to asss.atreides.b01lersc.tf on port 8443
[x] Opening connection to asss.atreides.b01lersc.tf on port 8443: Trying 34.57.227.210
[+] Opening connection to asss.atreides.b01lersc.tf on port 8443: Done
[*] Closed connection to asss.atreides.b01lersc.tf port 8443
a[8] = 14455295037286808417
y[8] = 26130864457331260309346011099837968783524620309360548685280088318670053168099095773375539197536284213340387759866015970257949195755392800546477962046901137467292045205670127036583816852741254226519477230718927048230716358267158856227709383342013422187129898474303292550305260281882180636800456975085461310087701589271571492158692567498358049813980389549130517158649127337618701435023529446004377320316648
y[8] % a[8] = 6197428082433649106

Reconstructed s = 337708554710955466011037307999326379017191231501903768452150849199069767557138107094684656013562309143653428295616878823098066670001067341236464224272006005885
Flag = bctf{shamir_secret_sharing_isn't_ass_but_this_implementation_isXD}
```

The recovered flag is: `bctf{shamir_secret_sharing_isn't_ass_but_this_implementation_isXD}`

## Resources
- Shamir's Secret Sharing: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
- Chinese Remainder Theorem: https://en.wikipedia.org/wiki/Chinese_remainder_theorem