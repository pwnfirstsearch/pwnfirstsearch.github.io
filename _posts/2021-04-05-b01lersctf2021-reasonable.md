---
layout: post
title:  "b01lers CTF 2021: Reasonable Security Ahead"
date:   2021-04-05
author: oneup
tags:   [crypto, rsa, franklinreiter]
---

# Reasonable Security Ahead

Solved by: oneup, inukai

## Problem statement

> We have infiltrated the shadowy organization and set up a tunnel to
their secret mainframe (nc chal.b01lers.com 25002). Unfortunately,
any server output is encrypted via plain RSA. All is not lost,
however, because a trusted insider can provide temporary access to
their test server (nc chal.b01lers.com 25001). The test server has an
additional feature that allows for toggling encryption on and off
through a modified output function

```python
   def output(self, msg):
       if self.debug: print(msg)
       else:          normal_encrypted_output(msg)
```

> Your mission, should you accept it, is to leverage the given access
and extract the secret data from the mainframe within the next 48
hours. Time is critical, so manage resources wisely. This message
will self-destruct in 5.. 4.. 3.. 2.. 1..

## Server output

(note: numbers are truncated for readability, the actual output had
the full numbers)

Connecting to the test server, we're presented with a menu and can
do the following things:

```
1) show key
2) encryption test
3) encrypt something
4) show secret
5) encrypt secret
6) display menu
7) toggle testing mode [available on TEST SERVER ONLY]
Choose:
1
p=1511...3377
q=9754...8337
e=11111
Choose:
2
encryption of 'THIS IS A TEST' gives:
0x70cb...9ff4
Choose:
3
Message:
xyz
encryption of 'xyz' gives:
0x45e1...9d1e
Choose:
4
fakeflag{This is not the real flag!!}
Choose:
5
encryption of 'fakeflag{This is not the real flag!!}' gives:
0x406f...26b7
Choose:
```

Connecting to the real server, we get the following:

```
0x8bb7...cf80
0x43af...2e83
0x6de2...a0d9
0x6092...22dc
0x2b68...c361
0x70ed...abf9
0x9f7c...cbbd
1
0x9211...2526
0x1fdc...eaac
0xa5de...9329
0x9f7c...cbbd
2
0x9144...6bd4
0x2295...db61
0x9f7c...cbbd
3
0xd900...8697
xyz
0x8b04...0c1f
0x7cc2...5f56
0x9f7c...cbbd
4
0xc779...0c99
0x9f7c...cbbd
5
0x674b...036d
0xa996...bb65
0x9f7c...cbbd
```

## Solution

### RSA configuration

First things first. Is this textbook RSA where we just calculate
`C = pow(M, e, N)`? Or is this real RSA where we actually add padding
etc.

To find out, we can connect to the test server, get the key, put it
into encrypting mode, and compare the output to what we calculate
ourselves:

```
1) show key
2) encryption test
3) encrypt something
4) show secret
5) encrypt secret
6) display menu
7) toggle testing mode [available on TEST SERVER ONLY]
Choose:
1
p=1511...3377
q=9754...8337
e=11111
Choose:
7
0x8dfe...54cd   # ed: this should be the "Choose:" message, encrypted
```

Compare to:

```python
#!/usr/bin/env sage

def encode_text(s):
    if type(s) is str:
        s = s.encode('ascii')
    return int.from_bytes(s, 'big')

p = 1511...3377
q = 9754...8337
e = 11111
N = p * q
M = encode_text('Choose:')
C = pow(M, e, N)
print('C:', hex(C))

# Output:
# C: 0x8dfe...54cd
```

It's a match, so we're attacking plain RSA without padding.

### Public Key

Sanity check. They're not using the same key between the test server
and real server, right?

Test server:

```
1) show key
2) encryption test
3) encrypt something
4) show secret
5) encrypt secret
6) display menu
7) toggle testing mode [available on TEST SERVER ONLY]
Choose:
1
p=1511...3377
q=9754...8337
e=11111
Choose:
7
0x8dfe...54cd   # ed: Choose:
```

Real server:
```
0x8bb7...cf80   # ed: 1) show key
0x43af...2e83   # ed: 2) encryption test
0x6de2...a0d9   # ed: 3) encrypt something
0x6092...22dc   # ed: 4) show secret
0x2b68...c361   # ed: 5) encrypt secret
0x70ed...abf9   # ed: 6) display menu
0x9f7c...cbbd   # ed: Choose:
```

`0x8dfe...54cd` and `0x9f7c...cbbd` don't match so we can verify
(unfortunately) that the two servers are using different keys.

Well now we're in a bit of a pickle. We basically have almost an
encryption oracle, which is even less useful than having a public
key. Even the encryption oracle isn't great because the output of the
oracle gets converted to ASCII and then re-encrypted a second time.

So can we derive the public key from an encryption oracle? The answer
is yes. All we need is two known plaintext and ciphertext pairs,
which we'll call M1, C1 and M2, C2.

From the definition of RSA, we have:

```python
C1 = M1 ** e (mod N)
C2 = M2 ** e (mod N)
```

From the definition of congruence, we know there exist 2 unknown
constants, k1 and k2, such that

```python
M1 ** e == k1 * N + C1
M2 ** e == k2 * N + C2
```

Swapping things around, we can calculate two numbers both divisible
by N:

```python
M1 ** e - C1 == k1 * N
M2 ** e - C2 == k2 * N
```

From here, we can take the GCD to extract N. (Technically a multiple
of N. If k1 and k2 aren't coprime, then GCD(k1, k2) != 1 and we end
up getting GCD(k1, k2) * N. In practice though, this didn't happen so
we don't even need to think about whether or not it's a problem. Off
the top of my head, I think the way around this would be to just use
more plaintext/ciphertext pairs.)

```python
N = GCD(M1 ** e - C1, M2 ** e - C2)
```

We originally hoped that e was at least the same between the two
servers. Unfortunately this ended up not being the case. However,
we were able to perform the above calculation in a loop for each
possible e.

Put it all together and we can use the following to solve for e and
N:

```python
#!/usr/bin/env sage

M1 = encode_text('1) show key')
M2 = encode_text('2) encryption test')

C1 = 0x8bb7...cf80
C2 = 0x43af...2e83

e = 1
while True:
    N = GCD(M1 ** e - C1, M2 ** e - C2)
    print(e, N)
    e += 1
```

Let the script run for a few minutes, and it finally prints something
out where the GCD isn't 1:

```
12395 0x1
12396 0x1
12397 0xb466...d9ff
```

Verify correctness against another line:

Real server:
```
0x8bb7...cf80   # ed: 1) show key
0x43af...2e83   # ed: 2) encryption test
0x6de2...a0d9   # ed: 3) encrypt something
0x6092...22dc   # ed: 4) show secret
0x2b68...c361   # ed: 5) encrypt secret
0x70ed...abf9   # ed: 6) display menu
0x9f7c...cbbd   # ed: Choose:
```

```python
#!/usr/bin/env sage

e = 12397
N = 0xb466...d9ff
M = encode_text('Choose:')
C = pow(M, e, N)
print('C:', hex(C))

# Output:
# C: 0x9f7c...cbbd
```

Public key confirmed.

### Decrypting the secret

RSA with no padding means that we should be able to do a
Franklin-Reiter related message attack if we can find two related
messages... and thankfully the server is more than happy to oblige.

Test server:

```
1) show key
2) encryption test
3) encrypt something
4) show secret
5) encrypt secret
6) display menu
7) toggle testing mode [available on TEST SERVER ONLY]
Choose:
4
fakeflag{This is not the real flag!!}                               # ed: <------ message 1
Choose:
5
encryption of 'fakeflag{This is not the real flag!!}' gives:        # ed: <------ message 2
0x406f...26b7
Choose:
```

And the corresponding messages on the real server:

```
0x8bb7...cf80   # ed: 1) show key
0x43af...2e83   # ed: 2) encryption test
0x6de2...a0d9   # ed: 3) encrypt something
0x6092...22dc   # ed: 4) show secret
0x2b68...c361   # ed: 5) encrypt secret
0x70ed...abf9   # ed: 6) display menu
0x9f7c...cbbd   # ed: Choose
4
0xc779...0c99   # ed: <unknown flag>                            <------- message 1
0x9f7c...cbbd   # ed: Choose
5
0x674b...036d   # ed: encryption of '<unknown flag>' gives:     <------- message 2
0xa996...bb65   # ed: <unknown hex value of encrypted unknown flag>
0x9f7c...cbbd   # ed: Choose
```

Let `M1` be the first message with just the flag, and let `M2` be the
second message with surrounding text, and let `flaglen` be the length
of the flag. Then we can create an affine relation between `M1` and
`M2`:

```python
text_upper = "encryption of '"
text_lower = "' gives:"

a = 8 * len(text_lower)
b_upper = encode_text(text_upper) * (2 ** 8 * (flaglen + len(text_lower)))
b_lower = encode_text(text_lower)
b = b_upper + b_lower
```

And now `M2 = a * M1 + b`.

Shoutouts to ashutosh1206 for publicly releasing a
[Sage script](https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Franklin-Reiter)
for Franklin-Reiter in their Github library, Crypton.

(Note that in ashutosh1206's implementation, C2 is the encrypted form
of the *simpler* plaintext and C1 is the encrypted form of the more
complex plaintext, which is opposite from how I've labelled M1 and M2
above.)

Unfortunately we don't know the length of the flag. But we can assume
the flag is probably less than 100 characters and try every possible
length from 1 to 100.

Each attempt takes around 6m30s to run. Thankfully with Python
`multiprocessing` it's pretty trivial to parallelize (note that
`threading` won't give you any speedup in cpython because of the
GIL). Now we can attempt 16 different flag lengths every 6m30s,
giving us a worst case runtime less than an hour for any flag less
than 100 chars.

```python
#!/usr/bin/env sage

# Modified from https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Franklin-Reiter/exploit.sage
# https://github.com/ashutosh1206/Crypton/blob/master/LICENSE

from sage.all import *

# All the variable names mean the same as mentioned in the explanation
# For eg, a,b are the values in the function f = ax + b

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a.monic()

def franklinreiter(C1, C2, e, N, a, b):
    P.<X> = PolynomialRing(Zmod(N))
    g1 = (a*X + b)^e - C1
    g2 = X^e - C2
    return -gcd(g1, g2).coefficients()[0]

# ------- ^ franklinreiter code ^ ------
# ------- v solution code v ------

from multiprocessing import Pool

def try_one(args):
    C1, C2, e, N, tgtlen = args

    text_upper = "encryption of '"
    text_lower = "' gives:"

    a = 2 ** (8 * len(text_lower))
    b_upper = encode_text(text_upper) * (2 ** (8 * (tgtlen + len(text_lower))))
    b_lower = encode_text(text_lower)
    b = b_upper + b_lower

    return tgtlen, franklinreiter(C1, C2, e, N, a, b)

C1 = 0x674b...036d
C2 = 0xc779...0c99
e = 12397
N = 0xb466...d9ff
pool = Pool()
arglist = [(C1, C2, e, N, i) for i in range(1,100)]
for tgtlen, result in pool.imap_unordered(try_one, arglist):
    print(tgtlen, hex(result))
```

Let it run for a while. You should get a batch of results every 5-10
minutes, where the size of the batch is variable on how many cores
you have. Wrong answers will give a value of N-1.

After 30-60 minutes you should get the flag:

```
55 0x6263...2e7d
```

```python
>>> bytes.fromhex('6263...2e7d')
b'bctf{Ye4h_rsa_w1th0u7_good_r4ndom_padd1ng_is_br0k3n...}'
```
