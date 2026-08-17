# examples/InstructionTour.smali
#
# One class that exercises every Dalvik instruction family, annotated line by
# line. Read it top to bottom once; after that, use it to look up "what does that
# family look like in real code".
#
# Every method here also carries its register-frame arithmetic in a comment, so
# the file doubles as a worked set of the calculation in README section 2.4.
#
# CHECK THE FRAMES YOURSELF
#     python3 ../scripts/smali_frame.py InstructionTour.smali
#     python3 ../scripts/smali_frame.py InstructionTour.smali --check
#
# PROFILE IT
#     python3 ../scripts/smali_stats.py InstructionTour.smali --top 40
#
# Families covered, in order of appearance:
#     const, iget/iput, sget/sput, invoke-direct/-static/-virtual/-interface,
#     invoke-static/range, return family, move family, arithmetic in all four
#     shapes, conversions, comparison, conditional and unconditional branches,
#     new-instance, new-array, aget/aput, fill-array-data, array-length,
#     instance-of, check-cast, packed-switch, sparse-switch, try/catch,
#     catchall (finally), monitor-enter/-exit, throw.

.class public Lcom/example/tour/InstructionTour;
.super Ljava/lang/Object;
.source "InstructionTour.java"

.implements Ljava/io/Closeable;


# static fields
.field private static final TAG:Ljava/lang/String; = "TOUR"
.field private static counter:I


# instance fields
.field private final key:[B
.field private open:Z
.field private lock:Ljava/lang/Object;


# ===========================================================================
# <clinit> -- the static initialiser. Runs ONCE, the first time the class is
# actively used (a static field read, a static call, or an instantiation).
# ===========================================================================
.method static constructor <clinit>()V
    .registers 1
    # static, ins_size = 0, so first param reg = 1 - 0 = 1, and there are no
    # parameters at all. v0 is the only register and it is a local.

    const/4 v0, 0x0                     # 11n -- 4-bit signed literal, -8..+7
    sput v0, Lcom/example/tour/InstructionTour;->counter:I
    return-void
.end method


# ===========================================================================
# <init> -- an instance constructor. ALWAYS begins with a super() or this()
# call, always invoke-direct.
# ===========================================================================
.method public constructor <init>([B)V
    .registers 3
    # ins_size = 2 (this + the byte array). first param reg = 3 - 2 = 1.
    #     p0 == v1   this
    #     p1 == v2   key
    #     v0         free local
    .param p1, "key"    # [B

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    # iput reads VALUE, OBJECT, FIELD.
    iput-object p1, p0, Lcom/example/tour/InstructionTour;->key:[B

    const/4 v0, 0x1
    iput-boolean v0, p0, Lcom/example/tour/InstructionTour;->open:Z

    # new-instance allocates; it does NOT run the constructor. Between these two
    # instructions v0 holds an UNINITIALISED reference and may not be stored,
    # passed or returned. That is a verifier state, not a convention.
    new-instance v0, Ljava/lang/Object;
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    iput-object v0, p0, Lcom/example/tour/InstructionTour;->lock:Ljava/lang/Object;

    # sget/sput on this class do not re-trigger <clinit>: it has already run.
    sget v0, Lcom/example/tour/InstructionTour;->counter:I
    add-int/lit8 v0, v0, 0x1            # 22b -- 8-bit signed literal
    sput v0, Lcom/example/tour/InstructionTour;->counter:I

    return-void
.end method


# ===========================================================================
# The register-frame example from README section 9.2.
# A long parameter consumes TWO registers and TWO p numbers.
# ===========================================================================
.method public transfer(Ljava/lang/String;JLjava/lang/String;)Z
    .registers 9
    # Count WORDS, not commas:
    #     this (1) + String (1) + long (2) + String (1)  =  ins_size 5
    # first param reg = 9 - 5 = 4
    #     p0 == v4   this
    #     p1 == v5   to
    #     p2 == v6   amount, LOW half     -- the long occupies v6:v7
    #     p3 == v7   amount, high half
    #     p4 == v8   memo
    #     v0..v3     free locals
    #
    # The second String is p4, not p3. Counting parameters instead of words is
    # the single most common way to get this wrong.
    .param p1, "to"        # Ljava/lang/String;
    .param p2, "amount"    # J
    .param p4, "memo"      # Ljava/lang/String;

    const-wide/16 v0, 0x0               # 21s, sign-extended to 64 -- v0:v1 = 0

    # cmp-long produces -1, 0 or +1 in a register. Dalvik has no combined
    # compare-and-branch for 64-bit values, so it always takes two instructions.
    cmp-long v2, v6, v0                 # 23x -- compare amount against zero
    if-lez v2, :cond_reject             # 21t -- branch if v2 <= 0

    iget-boolean v3, p0, Lcom/example/tour/InstructionTour;->open:Z
    if-eqz v3, :cond_reject             # "if not open" -- on a Z, eqz means false

    invoke-virtual {p1}, Ljava/lang/String;->length()I
    move-result v2                      # MUST be adjacent to the invoke above
    if-lez v2, :cond_reject

    const/4 v2, 0x1
    return v2

    :cond_reject
    const/4 v2, 0x0
    return v2
.end method


# ===========================================================================
# ARITHMETIC in all four shapes.
# ===========================================================================
.method public static mix(II)I
    .registers 4
    # static, ins_size = 2, first param reg = 4 - 2 = 2.
    #     p0 == v2   a
    #     p1 == v3   b
    #     v0, v1     free locals

    # three-register form: 23x, all operands named
    add-int v0, v2, v3                  # v0 = a + b

    # /lit8 form: 22b, the last operand is an 8-bit signed literal
    mul-int/lit8 v0, v0, 0x1f           # v0 = v0 * 31

    # /lit16 form: 22s, 16-bit signed literal
    add-int/lit16 v0, v0, 0x3e8         # v0 = v0 + 1000

    # /2addr form: 12x, destination is also the first source
    xor-int/2addr v0, v3                # v0 = v0 ^ b

    # rsub-int computes LITERAL minus REGISTER. It exists because there is no
    # sub-int/lit form: `x - 5` is add-int/lit8 with -5, but `5 - x` cannot be
    # expressed that way. Note it carries NO /lit16 suffix -- a wart in the spec.
    rsub-int v1, v0, 0x64               # v1 = 100 - v0

    # shifts have /lit8 but no /lit16, because the shift amount is masked to 5
    # bits for int (6 for long) and a 16-bit literal would be pointless.
    ushr-int/lit8 v1, v1, 0x18          # v1 = v1 >>> 24  (top byte)
    and-int/lit16 v1, v1, 0xff

    # unary
    neg-int v0, v1                      # 12x
    not-int v0, v0                      # bitwise NOT, i.e. xor with -1

    return v0
.end method


# ===========================================================================
# CONVERSIONS, and what happens to register footprints.
# ===========================================================================
.method public static widths(I)D
    .registers 5
    # static, ins_size = 1, first param reg = 5 - 1 = 4.
    #     p0 == v4   n
    #     v0..v3     free locals

    int-to-long v0, p0                  # writes v0:v1 -- v1 is CLOBBERED
    long-to-double v2, v0               # writes v2:v3
    double-to-float v0, v2              # writes v0 only; v1 is now free again
    float-to-int v0, v0
    int-to-byte v0, v0                  # narrowing within 32 bits, sign-extends
    int-to-char v0, v0                  # narrowing, ZERO-extends
    int-to-double v2, v0
    return-wide v2
.end method


# ===========================================================================
# FLOATING-POINT COMPARISON, and the l/g distinction.
# ===========================================================================
.method public static ratio(FF)Z
    .registers 4
    # static, ins_size = 2, first param reg = 2.
    #     p0 == v2, p1 == v3

    # cmpl-* yields -1 when either operand is NaN; cmpg-* yields +1. The compiler
    # picks whichever makes the FOLLOWING branch produce correct Java semantics,
    # because `a < b` and `a > b` must BOTH be false when either side is NaN, and
    # one comparison instruction cannot deliver both.
    cmpg-float v0, v2, v3
    if-gez v0, :cond_no

    const/4 v0, 0x1
    return v0

    :cond_no
    const/4 v0, 0x0
    return v0
.end method


# ===========================================================================
# ARRAYS: allocation, element access, array-length, and a literal payload.
# ===========================================================================
.method public static checksum([B)I
    .registers 6
    # static, ins_size = 1, first param reg = 6 - 1 = 5.
    #     p0 == v5   data
    #     v0..v4     free locals

    const/4 v0, 0x0                     # sum
    const/4 v1, 0x0                     # index

    :goto_loop
    array-length v2, p0                 # 12x
    if-ge v1, v2, :cond_done            # 22t

    # aget reads DEST, ARRAY, INDEX. aget-byte SIGN-extends the 8-bit value.
    aget-byte v3, p0, v1
    and-int/lit16 v3, v3, 0xff          # undo the sign extension

    add-int/2addr v0, v3
    add-int/lit8 v1, v1, 0x1
    goto :goto_loop

    :cond_done
    return v0
.end method

.method public static key()[B
    .registers 1
    # static, ins_size = 0. v0 is the only register.

    const/16 v0, 0x10                   # 21s -- 16
    new-array v0, v0, [B                # 22c -- allocate byte[16]

    # fill-array-data branches to a payload elsewhere in the instruction stream.
    # THIS IS WHERE HARDCODED KEYS LIVE. `strings` cannot find it, because the
    # payload is raw bytes and not text.
    fill-array-data v0, :array_0

    return-object v0

    # baksmali emits a bare nop here when one is needed to 4-byte-align the
    # payload. Do not "tidy it up" -- it is structural.
    nop

    :array_0
    .array-data 1                       # element width in BYTES: 1, 2, 4 or 8
        0x2bt
        0x7et
        0x15t
        0x16t
        0x28t
        -0x52t
        -0x2et
        -0x5at
        -0x55t
        -0x9t
        0x15t
        -0x78t
        0x9t
        -0x31t
        0x4ft
        0x3ct
    .end array-data
.end method

.method public static store([II)V
    .registers 4
    # static, ins_size = 2, first param reg = 2.
    #     p0 == v2   arr
    #     p1 == v3   value

    const/4 v0, 0x0
    # aput reads VALUE, ARRAY, INDEX -- the reverse of how you would say it.
    aput v3, p0, v0
    return-void
.end method


# ===========================================================================
# TYPE CHECKS.
# ===========================================================================
.method public static describe(Ljava/lang/Object;)Ljava/lang/String;
    .registers 3
    # static, ins_size = 1, first param reg = 2.  p0 == v2

    # instance-of writes 0 or 1 into a register.
    instance-of v0, p0, Ljava/lang/String;
    if-eqz v0, :cond_other

    # check-cast VALIDATES; it does not convert and it does not write a register.
    # It exists so the verifier can NARROW the register's type from here on.
    # Deleting one usually works at runtime and usually fails verification.
    check-cast p0, Ljava/lang/String;
    return-object p0

    :cond_other
    const-string v0, "not a string"
    return-object v0
.end method


# ===========================================================================
# STRING CONCATENATION -- the StringBuilder chain every `+` becomes.
# ===========================================================================
.method public static label(Ljava/lang/String;I)Ljava/lang/String;
    .registers 5
    # static, ins_size = 2, first param reg = 3.
    #     p0 == v3   name
    #     p1 == v4   n

    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "user="
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0              # append returns the builder; the chain threads it

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0

    const-string v1, ":"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0

    return-object v0
.end method


# ===========================================================================
# PACKED-SWITCH -- dense case values. The default is FALL-THROUGH.
# ===========================================================================
.method public static route(I)Ljava/lang/String;
    .registers 2
    # static, ins_size = 1, first param reg = 1.  p0 == v1, v0 is a local

    packed-switch p0, :pswitch_data_0

    # No case matched, so execution simply continues here. There is no default
    # target encoded anywhere in the instruction or the payload.
    const-string v0, "many"
    return-object v0

    :pswitch_0
    const-string v0, "zero"
    return-object v0

    :pswitch_1
    const-string v0, "one"
    return-object v0

    :pswitch_2
    const-string v0, "two"
    return-object v0

    :pswitch_data_0
    .packed-switch 0x0                  # first_key
        :pswitch_0                      # case 0
        :pswitch_1                      # case 1
        :pswitch_2                      # case 2
    .end packed-switch
.end method


# ===========================================================================
# SPARSE-SWITCH -- scattered case values. Keys MUST be sorted ascending,
# because the runtime binary-searches them.
# ===========================================================================
.method public static status(I)Ljava/lang/String;
    .registers 2
    # static, ins_size = 1, first param reg = 1.  p0 == v1

    sparse-switch p0, :sswitch_data_0

    const-string v0, "unknown"
    return-object v0

    :sswitch_0
    const-string v0, "ok"
    return-object v0

    :sswitch_1
    const-string v0, "not found"
    return-object v0

    :sswitch_2
    const-string v0, "server error"
    return-object v0

    :sswitch_data_0
    .sparse-switch
        0xc8 -> :sswitch_0              # 200
        0x194 -> :sswitch_1             # 404
        0x1f4 -> :sswitch_2             # 500
    .end sparse-switch
.end method


# ===========================================================================
# TRY / CATCH / FINALLY. There are no exception INSTRUCTIONS -- the whole
# mechanism is a table, written here as .catch and .catchall directives.
#
# Note that the finally body appears TWICE. That is the compiler duplicating it
# onto the normal path and the exception path. It is not obfuscation.
# ===========================================================================
.method public static parse(Ljava/lang/String;)I
    .registers 4
    # static, ins_size = 1, first param reg = 3.  p0 == v3

    :try_start_0
    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I
    move-result v0
    :try_end_0
    # The directive sits AFTER the region it protects. The range is half-open:
    # :try_start_0 up to but NOT including :try_end_0. Handlers are matched in
    # the order the directives appear, so a subclass must be listed first.
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    # finally, copy 1 -- the normal path
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;
    const-string v2, "TOUR done"
    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    return v0

    :catch_0
    move-exception v1                   # MUST be the handler's first instruction
    # finally, copy 2 -- the typed-catch path
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;
    const-string v2, "TOUR done"
    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    const/4 v0, -0x1
    return v0

    :catchall_0
    move-exception v1
    # finally, copy 3 -- the rethrow path. This is how `finally` is actually
    # implemented: a catch-everything handler that runs the body and rethrows.
    sget-object v2, Ljava/lang/System;->out:Ljava/io/PrintStream;
    const-string v0, "TOUR done"
    invoke-virtual {v2, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
    throw v1
.end method


# ===========================================================================
# SYNCHRONIZED BLOCK. Note the catchall that releases the monitor on the
# exception path -- without it, an exception would leave the lock held forever.
#
# A synchronized METHOD has none of these instructions: the
# declared-synchronized access flag tells the runtime to take the lock on entry.
# ===========================================================================
.method public bump()I
    .registers 4
    # ins_size = 1 (this only). first param reg = 4 - 1 = 3.  p0 == v3

    iget-object v0, p0, Lcom/example/tour/InstructionTour;->lock:Ljava/lang/Object;
    monitor-enter v0

    :try_start_0
    sget v1, Lcom/example/tour/InstructionTour;->counter:I
    add-int/lit8 v1, v1, 0x1
    sput v1, Lcom/example/tour/InstructionTour;->counter:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0
    return v1

    :catchall_0
    move-exception v2
    monitor-exit v0
    throw v2
.end method


# ===========================================================================
# INVOKE-STATIC/RANGE. The 35c form can name at most FIVE register words and
# none above v15. Six long-halves need the range form -- and the arguments must
# ALREADY be contiguous, which is why the caller lays them out with three
# const-wide instructions into v0:v1, v2:v3, v4:v5.
# ===========================================================================
.method public static wide6(JJJ)J
    .registers 12
    # static, ins_size = 6 (three longs, two words each). first param reg = 6.
    #     p0 == v6,  p1 == v7    -- first long,  v6:v7
    #     p2 == v8,  p3 == v9    -- second long, v8:v9
    #     p4 == v10, p5 == v11   -- third long,  v10:v11
    #     v0..v5 free locals

    move-wide v0, v6
    add-long/2addr v0, v8
    add-long/2addr v0, v10
    return-wide v0
.end method

.method public static callWide()J
    .registers 8
    # static, ins_size = 0. Every register is a local.

    const-wide/16 v0, 0x1               # v0:v1
    const-wide/16 v2, 0x2               # v2:v3
    const-wide/16 v4, 0x3               # v4:v5

    invoke-static/range {v0 .. v5}, Lcom/example/tour/InstructionTour;->wide6(JJJ)J
    move-result-wide v6

    return-wide v6
.end method


# ===========================================================================
# The MOVE family, and the register-width escape hatches.
# ===========================================================================
.method public static moves(Ljava/lang/Object;)Ljava/lang/Object;
    .registers 20
    # static, ins_size = 1, first param reg = 20 - 1 = 19.  p0 == v19
    #
    # p0 lives ABOVE v15, so any instruction with a 4-bit register field cannot
    # touch it directly. This method exists to show the three ways round that.

    # move-object/from16 has an 8-bit destination and a 16-bit source, so it can
    # bring a high register down into a low one.
    move-object/from16 v0, p0

    # Now v0 is reachable by every 4-bit-field instruction.
    move-object v1, v0                  # 12x, both fields 4 bits

    # move-object/16 widens BOTH fields to 16 bits.
    move-object/16 v18, v1

    # 32-bit and 64-bit moves have the same three widths.
    const/16 v2, 0x7b
    move v3, v2                         # 12x
    move/from16 v17, v2                 # 22x
    const-wide/16 v4, 0x2a
    move-wide v6, v4                    # 12x, moves v4:v5 into v6:v7

    return-object v1
.end method


# ===========================================================================
# INVOKE-INTERFACE, and the reason it matters when you are grepping.
# ===========================================================================
.method public static firstOf(Ljava/util/List;)Ljava/lang/Object;
    .registers 3
    # static, ins_size = 1, first param reg = 2.  p0 == v2

    # The static type at the call site is an interface, so the actual code that
    # runs could be in ANY class implementing List. Grepping for "List" will not
    # lead you to ArrayList's implementation.
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z
    move-result v0
    if-eqz v0, :cond_has

    const/4 v0, 0x0
    return-object v0                    # null IS const/4 0 -- the OPCODE carries
                                        # the "this is a reference" information

    :cond_has
    const/4 v0, 0x0
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;
    move-result-object v0
    return-object v0
.end method


# ===========================================================================
# THROW, and a private method reached by invoke-direct.
# ===========================================================================
.method private requireOpen()V
    .registers 4
    # ins_size = 1, first param reg = 3.  p0 == v3

    iget-boolean v0, p0, Lcom/example/tour/InstructionTour;->open:Z
    if-nez v0, :cond_ok

    new-instance v0, Ljava/lang/IllegalStateException;
    const-string v1, "closed"
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V
    throw v0

    :cond_ok
    return-void
.end method

.method public close()V
    .registers 2
    # ins_size = 1, first param reg = 1.  p0 == v1

    # invoke-direct on something that is NOT <init> means the target is PRIVATE.
    # That single fact is one of the most useful reading shortcuts in Smali.
    invoke-direct {p0}, Lcom/example/tour/InstructionTour;->requireOpen()V

    const/4 v0, 0x0
    iput-boolean v0, p0, Lcom/example/tour/InstructionTour;->open:Z
    return-void
.end method
