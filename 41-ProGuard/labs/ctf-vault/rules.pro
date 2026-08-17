# labs/ctf-vault/rules.pro
#
# The rules file that ships with the CH41 CTF.
#
# It was written by a developer who wanted five things preserved and believed
# this file preserved all five. Read it before you build anything, decide what
# each rule really does, and write down your prediction. Then build, and see
# how many of your five predictions were right.
#
# Nothing here is a trick of syntax. Every rule is valid, every rule parses,
# and the build succeeds without a single warning. That is the point: the
# language will not tell you when a rule is wrong, only when it is malformed.

# --------------------------------------------------------------------------
# The entry point. AGP would generate this from the manifest; build.sh drives
# R8 directly, so it is written out here.
# --------------------------------------------------------------------------
-keep class com.pentest.ch41.ctf.Gate { <init>(...); }

# --------------------------------------------------------------------------
# "Keep the enum constants, because we read their names."
# --------------------------------------------------------------------------
-keepclassmembers enum com.pentest.ch41.ctf.Stage {
    *;
}

# --------------------------------------------------------------------------
# "Keep the field NAMES on Holder, because we read them reflectively."
#
# Note which directive this is. It keeps names; it does not keep the class.
# --------------------------------------------------------------------------
-keepclassmembernames class com.pentest.ch41.ctf.Holder {
    <fields>;
}

# --------------------------------------------------------------------------
# "Keep everything under com.pentest.ch41.ctf, because we load some of it
#  reflectively and I would rather not work out which."
#
# This is the rule the challenge is named after.
# --------------------------------------------------------------------------
-keep class com.pentest.ch41.ctf.* {
    *;
}

# --------------------------------------------------------------------------
# Stack traces that resolve, without publishing source filenames.
# --------------------------------------------------------------------------
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
