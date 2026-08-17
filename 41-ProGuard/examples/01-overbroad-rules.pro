# examples/01-overbroad-rules.pro
#
# THE BAD ONE. A deliberately over-broad rules file, written the way real ones
# get written: someone hit a ClassNotFoundException the week before ship, added
# a wildcard until the crash stopped, and never came back.
#
# Every rule below is syntactically valid and every rule below is real -- each
# one is a shape I have read in a production proguard-rules.pro. Read it top to
# bottom with examples/02-tightened-rules.pro open beside it.
#
# HOW TO USE IT
#   ./keeplab/build.sh                  # builds A, B and C; C uses this file
#   python3 -B ../scripts/proguard-rules-audit.py 01-overbroad-rules.pro
#
# WHAT THIS FILE COSTS, MEASURED
#   Section 9 of the chapter README prints the numbers this file produced on
#   the fixture. The headline: it puts every original class, method and field
#   name back into the DEX, and it re-admits a dead class carrying a staging
#   token that the tightened build had removed.
#
# THIS FILE IS A TEACHING ARTEFACT. Do not paste it into a project.

# --------------------------------------------------------------------------
# THE ONE LINE THAT UNDOES EVERYTHING
# --------------------------------------------------------------------------
# `**` crosses package separators, so this matches com.pentest.ch41.MainActivity
# AND com.pentest.ch41.internal.crypto.KeyWrapper AND everything else the app
# will ever contain. `{ *; }` then keeps every field and every method of every
# one of those classes.
#
# The consequences, in order of how badly they are understood:
#
#   1. Nothing in your own code is renamed.          (widely understood)
#   2. Nothing in your own code is SHRUNK.           (rarely understood)
#   3. Nothing in your own code is OPTIMISED --      (almost never understood)
#      no inlining, no class merging, no dead-branch
#      elimination inside kept members.
#
# Point 2 is the one that shows up in an assessment: dead classes, leftover
# debug helpers and staging constants that tree shaking would have deleted are
# all still in the shipped APK.
-keep class com.pentest.ch41.** { *; }

# --------------------------------------------------------------------------
# "we use reflection somewhere"
# --------------------------------------------------------------------------
# Written by someone who knew ONE class was loaded reflectively and could not
# remember which. It keeps every class in the app that has any annotation at
# all -- which, in a project using AndroidX, Room, Dagger or Retrofit, is most
# of them.
-keepclassmembers class * {
    @** *;
}

# --------------------------------------------------------------------------
# "the crash reports were unreadable"
# --------------------------------------------------------------------------
# -dontobfuscate is the nuclear version of this. It disables renaming globally
# while leaving shrinking and optimisation on, so the build looks like it is
# doing something. What the developer actually wanted was
# -keepattributes SourceFile,LineNumberTable plus -renamesourcefileattribute,
# which keeps stack traces resolvable THROUGH the mapping file without giving
# the names away. See examples/02.
-dontobfuscate

# --------------------------------------------------------------------------
# "R8 broke our JSON"
# --------------------------------------------------------------------------
# Correct instinct, wrong scope. The model classes needed keeping; `class *`
# keeps the members of every class in the application, including libraries.
-keepclassmembers class * implements java.io.Serializable {
    *;
}

# --------------------------------------------------------------------------
# "just make the warnings stop"
# --------------------------------------------------------------------------
# -dontwarn ** silences every missing-class warning in the build, including the
# ones that mean "you are shipping a library that references code you do not
# have". Those warnings are how you find out a dependency is half-installed.
-dontwarn **

# --------------------------------------------------------------------------
# The attributes line nobody prunes
# --------------------------------------------------------------------------
# SourceFile and LineNumberTable together put the ORIGINAL .java filename and
# original line numbers back into the DEX. With -dontobfuscate above, an
# analyst gets original class names, original member names, original filenames
# and original line numbers -- which is the source tree, minus the bodies of
# the methods, handed over for free.
-keepattributes *
