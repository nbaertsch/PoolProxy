import std/macros
import std/sysrand

import winim/lean
import nimvoke/dinvoke

template debug(a: untyped) =
    when not defined release:
        a


#var ppCS: CRITICAL_SECTION # Critical Section for poolproxy calls

# initialize critical section on import
# ! OPSEC !
# https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectio
#if 0 == InitializeCriticalSectionEx(ppCS.addr, 100, CRITICAL_SECTION_NO_DEBUG_INFO):
#    debug:
#        echo "Failed to initialize poolproxy critical section"


dinvokeDefine(
    TpAllocWork,
    "ntdll.dll",
    proc (ppWork: ptr PTP_WORK, Callback: PTP_WORK_CALLBACK, Context: PVOID, CallbackEnviron: PTP_CALLBACK_ENVIRON,): NTSTATUS {.stdcall.}
)

dinvokeDefine(
    TpPostWork,
    "ntdll.dll",
    proc (pWork: PTP_WORK) {.stdcall.}
)

dinvokeDefine(
    TpReleaseWork,
    "ntdll.dll",
    proc (pWork: PTP_WORK) {.stdcall.}
)

dinvokeDefine(
    TpWaitForWork,
    "ntdll.dll",
    proc (pWork: PTP_WORK, CancelPendingCallbacks: LOGICAL) {.stdcall.}
)

dinvokeDefine(
    ZwProtectVirtualMemory,
    "ntdll.dll",
    proc (ProcessHandle: Handle, BaseAddress: PVOID, NumberOfBytesToProtect: PULONG, NewAccessProtection: ULONG, OldAccessProtection: PULONG): NTSTATUS {.stdcall.}
)


{.passL: "-Wl,--image-base -Wl,0x10000000".}
proc workCallbackStub*(instance: PTP_CALLBACK_INSTANCE, ctx: PVOID, work: PTP_WORK) {.stdcall, asmNoStackFrame.} =
    #EnterCriticalSection(ppCS.addr)
    #LeaveCriticalSEctionWhenCallbackReturns(instance, ppCS.addr)

    asm """
    code:
        push rbx                # this is popped in our gadget
        mov rbx, rdx
        mov r11, [rbx]          # sentinel 1

        mov rax, [rbx + 0x8]    # proxied funcAddr

        sub rsp, 0x40           # add stack space to account for our gadget

        cmp r11, [rbx + 0x18]   # reg arg 1
        je morecode
        mov rcx, [rbx + 0x18]

        cmp r11, [rbx + 0x20]   # reg arg 2
        je morecode
        mov rdx, [rbx + 0x20]

        cmp r11, [rbx + 0x28]   # reg arg 3
        je morecode
        mov r8, [rbx + 0x28]

        cmp r11, [rbx + 0x30]   # reg arg 4
        je morecode 
        mov r9, [rbx + 0x30]

        cmp r11, [rbx + 0x38]   # stack arg 1
        je morecode
        mov r10, [rbx + 0x38] 
        mov [rsp+0x20], r10

        cmp r11, [rbx + 0x40]   # stack arg 2
        je morecode
        mov r10, [rbx + 0x40] 
        mov [rsp+0x28], r10

        cmp r11, [rbx + 0x48]   # stack arg 3
        je morecode
        mov r10, [rbx + 0x48] 
        mov [rsp+0x30], r10

        cmp r11, [rbx + 0x50]   # stack arg 4
        je morecode
        mov r10, [rbx + 0x50] 
        mov [rsp+0x38], r10

        # There is no more space available in the forged stack frame, at least for this particular gadget.
    
    morecode:
        # we are reting to: (48 89 03 48 83 c4 40 5b c3) in ntdll.dll,RtlPcToFileHeader
            # mov [rbx], rax
            # add rsp, 40
            # pop rbx
        
        push [rbx + 0x10]       # address of our gadget
        jmp rax

    """

proc getRtlPcToFileHeaderGadget(): SIZE_T =
    let funcAddr = cast[SIZE_T](hashAsciiStatic("ntdll.dll").getProcAddressByHash(hashAsciiStatic("RtlPcToFileHeader")))
    return funcAddr + 36 # trust me bro, or look for the bytes: 48 89 03 48 83 c4 40 5b c3


proc coerceToSizeT*[T](t: T): SIZE_T =
    return cast[SIZE_T](t)


macro poolproxy*(funcName: untyped, libName: untyped, args: varargs[SIZE_T, coerceToSizeT]): untyped =
    ## Max of 8 args, anything more will fail
    let
        funcNameStr = funcName.strVal
        libNameStr = libName.strVal

    quote do:
        let funcAddr: SIZE_T = cast[SIZE_T](hashAsciiStatic(`libNameStr`).getProcAddressByHash(hashAsciiStatic(`funcNameStr`)))
        var context: seq[SIZE_T]
        let high = `args`.high

        # find an appropriate sentinel
        var
            rand = urandom(sizeof(SIZE_T))
            sentinel = cast[ptr SIZE_T](rand[0].addr)[]
            sentinelIsSafe: bool = true
        # check sentinel safety
        if (sentinel == cast[SIZE_T](funcAddr)): sentinelIsSafe = false
        for i in 0..high:
            if sentinel == `args`[i]: sentinelIsSafe = false

        # loop to ensure a safe sentinel
        while not sentinelIsSafe:
            rand = urandom(sizeof(SIZE_T))
            sentinel = cast[ptr SIZE_T](rand[0].addr)[]
            sentinelIsSafe = true
            # check sentinel safety
            if (sentinel == cast[SIZE_T](funcAddr)): sentinelIsSafe = false
            for i in 0..high:
                if sentinel == `args`[i]: sentinelIsSafe = false

        # add sentinel and funcAddr to the context struct
        context.add(sentinel)
        context.add(cast[SIZE_T](funcAddr))
        context.add(getRtlPcToFileHeaderGadget())

        # add the rest of the args to the context struct, inverting the stack args order
        for i in 0..high:
            if i <= 3:
                context.add(`args`[i]) # reg args
            else:
                context.add(`args`[i]) # context.add(`args`[high-(i-4)]) # stack args
        
        context.add(sentinel) # add last sentinel

        debug:
            echo "callback: ", toHex(cast[SIZE_T](workCallbackStub))
            for i in 0..context.high:
                echo "[", i, "] ", toHex(context[i])
            discard stdin.readline

        # create the work object and execute it.
        var
            pWork: PTP_WORK = NULL
            status = TpAllocWork(&pWork, workCallbackStub.PTP_WORK_CALLBACK, context[0].addr, NULL)  
        if status != 0:
            debug:
                echo "TpAllocWork failed: ntstatus= ", toHex(status)
        TpPostWork(pWork)
        TpWaitForWork(pWork, FALSE)
        TpReleaseWork(pWork)

        context[0] # return the rop-captured return value of the proxied function