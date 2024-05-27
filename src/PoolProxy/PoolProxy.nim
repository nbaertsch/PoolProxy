import std/macros
import std/sysrand

import winim/lean
import nimvoke/dinvoke

template debug(a: untyped) =
    when not defined release:
        a


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
    asm """
    code:
        mov rbx, rdx
        mov r11, [rbx]

        mov rax, [rbx + 0x8]    # no cmp since we jump to rax

        cmp r11, [rbx + 0x10]
        je morecode
        mov rcx, [rbx + 0x10]

        cmp r11, [rbx + 0x18]
        je morecode
        mov rdx, [rbx + 0x18]

        cmp r11, [rbx + 0x20]
        je morecode
        mov r8, [rbx + 0x20]

        cmp r11, [rbx + 0x28]
        je morecode 
        mov r9, [rbx + 0x28]

        cmp r11, [rbx + 0x30]
        je morecode
        mov r10, [rbx + 0x30] 
        mov [rsp+0x20], r10

        cmp r11, [rbx + 0x38]
        je morecode
        mov r10, [rbx + 0x38] 
        mov [rsp+0x28], r10

        cmp r11, [rbx + 0x40]
        je morecode
        mov r10, [rbx + 0x40] 
        mov [rsp+0x30], r10

        cmp r11, [rbx + 0x48]
        je morecode
        mov r10, [rbx + 0x48] 
        mov [rsp+0x38], r10

        # There is no more space available in the stack frame for the work callback from `TpAllocPool`
        # actually there is exactly one more qword available now that we are fucking with the stack frame and overwriting homing space

    morecode:
        lea r11, evenmorecode
        push r11
        jmp rax

    evenmorecode:
        mov [rbx], rax
    """


proc buildContextTpWork*(funcAddr: FARPROC, args: openArray[SIZE_T]): seq[SIZE_T] =
    ## Builds the context struct used for TP_WORK_CALLBACK's
    var context: seq[SIZE_T]
    let high = args.high
    
    var
        rand = urandom(sizeof(SIZE_T))
        sentinel = cast[ptr SIZE_T](rand[0].addr)[]
        sentinelIsSafe: bool = true
    
    # check sentinel safety
    if (sentinel == cast[SIZE_T](funcAddr)): sentinelIsSafe = false
    for i in 0..high:
        if sentinel == args[i]: sentinelIsSafe = false

    # loop to ensure a safe sentinel
    while not sentinelIsSafe:
        rand = urandom(sizeof(SIZE_T))
        sentinel = cast[ptr SIZE_T](rand[0].addr)[]
        sentinelIsSafe = true
        # check sentinel safety
        if (sentinel == cast[SIZE_T](funcAddr)): sentinelIsSafe = false
        for i in 0..high:
            if sentinel == args[i]: sentinelIsSafe = false
    
    echo sentinel.toHex() # debug
    context.add(sentinel)
    context.add(cast[SIZE_T](funcAddr))
    
    for i in 0..high:
        if i <= 3:
            context.add(args[i]) # reg args
        else:
            context.add(args[high-(i-4)]) # stack args, inverted order
    
    context.add(sentinel)
    
    return context


proc coerceToSizeT*[T](t: T): SIZE_T =
    return cast[SIZE_T](t)

#[
macro poolproxy*(funcName: untyped, libName: untyped, args: varargs[SIZE_T, coerceToSizeT]): SIZE_T =
    let
        funcNameStr = funcName.strVal
        libNameStr = libName.strVal

    quote do:
        #if `args`.len > 8: {.fatal:"poolproxy max args exceeded (8)".}
        let funcAddr: FARPROC = (hashAsciiStatic(`libNameStr`).getProcAddressByHash(hashAsciiStatic(`funcNameStr`)))
        var castedArgs: seq[SIZE_T]
        var context = buildContextTpWork(funcAddr, `args`)

        # create the work object and execute it.
        var
            pWork: PTP_WORK = NULL
            status = TpAllocWork(&pWork, workCallbackStub.PTP_WORK_CALLBACK, context[0].addr, NULL)  
        if status != 0:
            dbgEcho "TpAllocWork failed: ntstatus= ", toHex(status)
        TpPostWork(pWork)
        TpWaitForWork(pWork, FALSE)
        TpReleaseWork(pWork)
        context[0]
        
]#

macro poolproxy*(funcName: untyped, libName: untyped, args: varargs[SIZE_T, coerceToSizeT]): untyped =
    #if args.len > 8: {.fatal:"poolproxy max args exceeded (8)".}
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
        context[0]