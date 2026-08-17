# examples/Pinner.smali
#
# The certificate-pinning class walked through in README section 6.2, with every
# line annotated. The body is byte-for-byte the listing in the README; only the
# comments are added here.
#
# READ IT IN THIS ORDER -- header, fields, constructor, then the method. That is
# the order that gets you to the finding fastest, and on this class the header
# alone tells you what you are looking at.
#
# THE FINDING: verify() has a bypass flag. When 'strict' is false it returns
# true for every hostname and every certificate, which disables hostname
# verification and the pin together. See the bottom of this file.

.class public final Lcom/example/net/Pinner;
.super Ljava/lang/Object;
.source "Pinner.java"

# 'final' -- the class cannot be subclassed. Relevant because it means nobody
# overrides verify() elsewhere; what you read here is what runs.

# ---------------------------------------------------------------------------
# .implements tells you the whole story before you read a single instruction.
# HostnameVerifier is the interface Java's TLS stack calls to decide whether a
# certificate's subject matches the host being connected to.
# ---------------------------------------------------------------------------
.implements Ljavax/net/ssl/HostnameVerifier;


# static fields
# -------------
# A 'static final' String with an inline initialiser. The value is stored in the
# DEX's encoded_array for the class and is a compile-time constant -- it is right
# there in the file, no decryption, no resource lookup.
.field private static final PIN:Ljava/lang/String; = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


# instance fields
# ---------------
# 'final Z' set once in the constructor. THIS is the bypass flag. Find every
# construction site to learn what it is set to:
#     grep -rn -A4 'new-instance .*Lcom/example/net/Pinner;' smali*/
.field private final strict:Z


# direct methods
# --------------
# 'direct' means invoke-direct: constructors, private methods, and static
# methods. baksmali groups them before the virtual methods.

.method public constructor <init>(Z)V
    .registers 2
    # ins_size = 2 (this + the boolean). first param reg = 2 - 2 = 0.
    #   p0 == v0  this
    #   p1 == v1  strict
    # ZERO free locals. Any patch that needs a scratch register must raise this.
    .param p1, "strict"    # Z

    # Every constructor begins with a super() or this() call. It is invoke-direct
    # because constructors are never virtually dispatched.
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    # iput reads VALUE, OBJECT, FIELD -- v/p first, then the receiver.
    iput-boolean p1, p0, Lcom/example/net/Pinner;->strict:Z

    return-void
.end method


# virtual methods
# ---------------

.method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
    .registers 7
    # ins_size = 3 (this + String + SSLSession). first param reg = 7 - 3 = 4.
    #   p0 == v4  this
    #   p1 == v5  host
    #   p2 == v6  session
    # v0..v3 are free locals -- AND the body also reuses v4, v5 and v6 as scratch
    # once the parameters are dead. That is legal and normal, and it is exactly
    # why you must never raise .registers on this method without re-checking
    # every raw vN in the body. Run:
    #     python3 ../scripts/smali_frame.py Pinner.smali --check
    .param p1, "host"       # Ljava/lang/String;
    .param p2, "session"    # Ljavax/net/ssl/SSLSession;

    # --- the bypass ---------------------------------------------------------
    iget-boolean v0, p0, Lcom/example/net/Pinner;->strict:Z

    # POLARITY: the branch is taken when v0 is NON-zero. So the fall-through --
    # the two instructions immediately below -- is the 'strict == false' path.
    if-nez v0, :cond_8

    const/4 v0, 0x1
    return v0
    # ^^^ THIS IS THE FINDING. A HostnameVerifier that returns true accepts any
    #     hostname on any certificate the trust manager accepted, and this path
    #     never consults the pin at all.

    # --- the real check -----------------------------------------------------
    :cond_8
    :try_start_8
    # invoke-interface: the static type at the call site is an interface, so the
    # implementation could be any class implementing SSLSession. Grepping for
    # the interface will not find the implementation.
    invoke-interface {p2}, Ljavax/net/ssl/SSLSession;->getPeerCertificates()[Ljava/security/cert/Certificate;
    move-result-object v1
    # move-result-object MUST be adjacent to the invoke above. Inserting anything
    # between them is a VerifyError at class load.

    const/4 v2, 0x0
    # aget-object reads DEST, ARRAY, INDEX -- v2 = v1[v2]. Reusing v2 as both the
    # index and the destination is normal register economy.
    aget-object v2, v1, v2

    invoke-static {v2}, Lcom/example/net/Pinner;->sha256Pin(Ljava/security/cert/Certificate;)Ljava/lang/String;
    move-result-object v3

    # The pin constant, loaded again as a const-string. Note it is the same text
    # as the PIN field -- the compiler inlined the static final String.
    const-string v4, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    # Receiver first inside the braces: v4.equals(v3).
    invoke-virtual {v4, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v5
    :try_end_25
    # The .catch directive sits AFTER the region it protects. The range is
    # half-open: :try_start_8 up to but NOT including :try_end_25.
    .catch Ljavax/net/ssl/SSLPeerUnverifiedException; {:try_start_8 .. :try_end_25} :catch_27

    return v5

    :catch_27
    # move-exception must be the FIRST instruction of a handler. It is the only
    # place the exception object is available.
    move-exception v6
    const/4 v5, 0x0
    return v5
    # Failing closed on SSLPeerUnverifiedException is correct behaviour. The bug
    # is upstairs, not here.
.end method


# ===========================================================================
# THE FINDING, written the way a client will accept it
# ===========================================================================
#
# Title
#     Certificate pinning can be disabled by a constructor flag
#
# Evidence
#     com/example/net/Pinner.smali, verify():
#         iget-boolean v0, p0, Lcom/example/net/Pinner;->strict:Z
#         if-nez v0, :cond_8
#         const/4 v0, 0x1
#         return v0
#     Construction sites:
#         grep -rn -A4 'new-instance .*Lcom/example/net/Pinner;' smali*/
#     shows const/4 v1, 0x0 immediately before the invoke-direct in
#     NetworkModule.smali, so the release build constructs it with strict=false.
#
# Impact
#     Any network-position attacker holding a certificate the device trusts --
#     including a user-installed proxy CA -- can intercept and modify all
#     traffic. The pin is present in the code and has no effect.
#
# Remediation
#     Remove the flag. Use okhttp3.CertificatePinner or the platform Network
#     Security Configuration, both of which are declarative and cannot be
#     silently disabled by a constructor argument.
#
# Severity
#     High
#
# ===========================================================================
# TO TEST THE ENDPOINT ANYWAY, two equivalent patches
# ===========================================================================
#
#   (a) flip the polarity so the bypass path is the strict path:
#           if-nez v0, :cond_8      ->      if-eqz v0, :cond_8
#
#   (b) short-circuit the whole method -- put these two lines immediately after
#       .registers 7, before anything else:
#           const/4 v0, 0x1
#           return v0
#
#   (b) is the safer edit: it touches no existing register and no existing
#   branch, and v0 already exists in this frame.
