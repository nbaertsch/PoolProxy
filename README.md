

An old and yet-unpublished blog post follows...

# Malware Floaties - Staying Safe in the Thread Pool

Over the last few months, I've been digging into common techniques to evade endpoint controls: Dynamically resolving function addresses, direct and indirect syscalls, and now function proxying through the thread pool. To be clear this is not a new technique by any stretch - I stumbled on this technique reading the excellent blog post [Hiding in PlainSight](https://0xdarkvortex.dev/hiding-in-plainsight/) by [@NinjaParanoid](https://x.com/NinjaParanoid). 

## What?

The technique presented  in [Hiding in PlainSight](https://0xdarkvortex.dev/hiding-in-plainsight/) proposes the use of thread pool workers to make API calls with a clean callstack. The TLDR here is that, when you make a function call (whether a high level API, an Nt/Rtl API, or even an (in)direct system call), the callstack will have a return address to your malware on the stack. In most cases, your malware will be running in memory, and so this return address will point to _unbacked_ memory; this is a blatant indicator for EDR that something fishy is going on in your likely to get your process killed if/when the EDR takes control of the threads execution flow and walks the callstack. To keep it concise (go read the mentioned blog post), we can create a callback function to be executed by a thread in the thread pool with a clean callstack and pass it a single argument. This function can act as a sort of trampoline, where the argument is a pointer to the address of the function we want to proxy and the parameters to pass to the proxied function call. Sounds simple, and it actually is for the most part, so long as you don't care about the return value of the proxied function. Another issue with the technique as presented is that it uses a hand-crafted callback function for the specific Win32 API that is being proxied, `NtAllocateVirtualMemory`.

```asm
section .text

global WorkCallback
WorkCallback:
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; NtAllocateVirtualMemory
    mov rcx, [rbx + 0x8]        ; HANDLE ProcessHandle
    mov rdx, [rbx + 0x10]       ; PVOID *BaseAddress
    xor r8, r8                  ; ULONG_PTR ZeroBits
    mov r9, [rbx + 0x18]        ; PSIZE_T RegionSize
    mov r10, [rbx + 0x20]       ; ULONG Protect
    mov [rsp+0x30], r10         ; stack pointer for 6th arg
    mov r10, 0x3000             ; ULONG AllocationType
    mov [rsp+0x28], r10         ; stack pointer for 5th arg
    jmp rax
```

That's certainly not a sustainable way to write code if you plan on using this technique for more than a handful of Win32 APIs. So we have those two problems that I aimed to solve here - proxying arbitrary Win32 APIs, and capturing the result of the proxied call.
## Generic function proxying

Recently, I've been playing around with [macro's in nim](https://nim-lang.org/docs/macros.html) to minimize code duplication and wrap some functionality like [making syscalls](https://github.com/nbaertsch/nimvoke). You can see where this is going - I wanted to write some assembly that could proxy arbitrary Win32 API calls and wrap it up in some macro goodness to hopefully be able to call a function like this:

```nim
var status = poolproxy(NtAllocateVirtualMemory,
	"ntdll.dll",
	hProcess,
	&baseAddr,
	0.SIZE_T,
	&shellcodeSize,
	(MEM_RESERVE or MEM_COMMIT),
	PAGE_READWRITE
)
```

There where a few hurdles here that I felt made this worthy of a blog post. The first of which was crafting the assembly that would be somehow intelligent enough to handle a variable number of function arguments. I was stuck on this for awhile until a colleague proposed the use of [sentinel values](https://en.wikipedia.org/wiki/Sentinel_value) to indicate the end of the data structure.

Basically, our structure that we are passing to the trampoline will have all the values sandwiched in between two instances of a random sentinel value (after checking to make sure the sentinel value is not the same as any arguments). So our struct will look like this:

```
[sentinel value]
[proxied funcAddr]
[arg 1]
[arg 2]
[arg 3]
...
[sentienl value]
```

And we can write some assembly that, before handling each value as an arg, ensures that the value does not equal the sentinel value:

```asm
mov rbx, rdx            # rdx will get stomped with an arg
mov r11, [rbx]          # sentinel 1
mov rax, [rbx + 0x8]    # proxied funcAddr to rax

cmp r11, [rbx + 0x18]   # compare arg 1 to sentinel
je morecode             # jmp if equal
mov rcx, [rbx + 0x18]   # else, move arg 1 to rcx

...
```

Then when the value _does_ equal the sentinel value, jump to `morecode` which in this case is simply `jmp rax` which begins executing our proxied function.

With that problem out of the way, let's tackle...

## Capturing the return value
This turned out to be a bit more complicated than expected, mostly due to my lack of foresight. See, my first attempt at this was to simply push the value of another label, `moremorecode`, before the jump so that the `ret` from our proxied function would return execution there and we could capture the resulting value in `rax`. The astute reader will notice that this completely defeats the purpose of proxying the function in the first place, since the address space of our malware is now dirtying up the stack (`picman` here is our example malware, lets pretend its unbacked memory).

![Malware Floaties - Capture rax dirty stack.png](https://github.com/nbaertsch/PoolProxy/blob/main/img/Malware%20Floaties%20-%20Capture%20rax%20dirty%20stack.png)

So what to do? Well, when we `jmp` to the proxied function call, we have a pointer to our struct in `rbx`. According to the [Windows x64 ABI](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions) , `rbx` is nonvolatile - we can safely assume that it will be unchanged after our function call. If we can find a gadget somewhere that moves `rax` into some offset of `[rbx]`, then we can push the address of said gadget to the stack instead of our sketchy malware. Bonus points here if the gadget resides in a system dll thats likely to be loaded, like `ntdll.dll`. 

Enter `RtlPcToFileHeader`. The epilogue of this function is exactly what we need:

![Malware Floaties - RtlPsToFileHeader gadget.png](https://github.com/nbaertsch/PoolProxy/blob/main/img/Malware%20Floaties%20-%20RtlPsToFileHeader%20gadget.png)

You'll notice the `add rsp,40` and the `pop rbx`, both of these instructions work in our favor:
- `rbx` is nonvolatile as we mentioned, so its probably best for our trampoline to have a prologue that pushes it to the stack any way (though this wasn't causing issue so far)
- `add rsp,40` cleans up some stack space. This means we can craft a stack frame that has enough room for 4 stack args. This makes the stack frame look a lot more normal than just pushing the address of a gadget. Coincidentally, the size of this required stack frame is the same as in the `ret` to `TpAllocPool` stack frame we were using for our stack args in the first iteration without return value capture.

So lets update the callback function:

```asm
push rbx                # this is popped in our gadget
mov rbx, rdx
mov r11, [rbx]          # sentinel 1

mov rax, [rbx + 0x8]    # proxied funcAddr

sub rsp, 0x40           # add stack space to account for our gadget

cmp r11, [rbx + 0x18]   # reg arg 1
je morecode
mov rcx, [rbx + 0x18]

...

cmp r11, [rbx + 0x38]   # stack arg 1
je morecode
mov r10, [rbx + 0x38] 
mov [rsp+0x20], r10

...

morecode:
	push [rbx + 0x10]       # address of our gadget
	jmp rax
```

At the time of the proxied call, the stack looks like this:

![Malware Floaties - forged RtlPcToFileHeader stack frame.png](https://github.com/nbaertsch/PoolProxy/blob/main/img/Malware%20Floaties%20-%20forged%20RtlPcToFileHeader%20stack%20frame.png)

When the proxied function `ret`s, it will execute the gadget which captures the return value in `[rbx]`, cleans up the stack frame, and `ret`s to `TpAllocPool`. 

## Now what?

If you like nim, you can use [PoolProxy](https://github.com/nbaertsch/PoolProxy) to start proxying functions through the thread pool today! You may want to be careful as there is an opportunity for race conditions between when you make the proxied function call and when you go to read the value from `[rbx]`. There are a couple ways around that, some more elegant than other's, but I will leave that as an exercise for you if you choose to implement something similar into your own malware.
