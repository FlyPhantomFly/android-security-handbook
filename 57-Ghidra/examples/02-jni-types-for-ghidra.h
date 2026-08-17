/*
 * 02-jni-types-for-ghidra.h — minimal JNI type declarations for Ghidra.
 *
 * WHAT IT IS
 *   A self-contained, preprocessor-free header that Ghidra's C parser will
 *   accept, declaring just enough of the JNI type system to make decompiled
 *   JNI code readable.
 *
 * WHY IT EXISTS
 *   The NDK's real jni.h is not parse-friendly: it is full of #ifdef __cplusplus
 *   blocks, macro-based calling-convention annotations, and platform includes,
 *   and Ghidra's parser will fight you over all of it. The recommended route is
 *   still to import the prepared jni_all.gdt archive from the JNIAnalyzer
 *   project - see ../README.md section 3.8, route 1.
 *
 *   This file is route 2.5: for when you have no internet, no NDK, or a target
 *   whose jni.h you cannot obtain, and you need JNIEnv defined in the next two
 *   minutes.
 *
 * HOW TO USE IT
 *   1. File -> Parse C Source...
 *   2. Create a new profile (the "+" icon).
 *   3. Clear the default source list and add ONLY this file.
 *   4. Clear the default parse options; this header needs none.
 *   5. Parse to Program, or better, Parse to File and save a .gdt so you never
 *      repeat this.
 *   6. Then, on any JNI function:  press F  ->
 *        jstring Java_com_example_C_m(JNIEnv *env, jobject thiz, jstring arg)
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *   It does not declare all ~230 JNI functions. It declares the ~50 you
 *   actually meet in Android app libraries, at their CORRECT indices, with
 *   `void *reservedN` padding to keep every subsequent offset right. Adding
 *   more is mechanical: find the index in the JNI specification, replace the
 *   corresponding reserved slot, and adjust the padding count.
 *
 * OFFSET ARITHMETIC
 *   byte offset (64-bit) = index * 8
 *   byte offset (32-bit) = index * 4
 *   The first four slots are reserved by the specification, so the first real
 *   function (GetVersion) is at index 4.
 *
 * VERIFY BEFORE YOU RELY ON IT
 *   The ordering below follows the JNI specification and is stable, but if a
 *   report will depend on an offset, check it against
 *   libnativehelper/include_jni/jni.h in AOSP for the platform version you are
 *   testing. See ../references/README.md.
 */

/* ---------------------------------------------------------------- scalars */

typedef unsigned char  jboolean;   /* JNI_TRUE = 1, JNI_FALSE = 0 */
typedef signed char    jbyte;
typedef unsigned short jchar;
typedef short          jshort;
typedef int            jint;
typedef long long      jlong;
typedef float          jfloat;
typedef double         jdouble;
typedef jint           jsize;

/* ---------------------------------------------------------------- objects
 *
 * In C these are all `void *` under the hood. Declaring them as DISTINCT
 * pointer types is what makes the decompiler show you `jstring` rather than
 * `void *`, which is most of the readability benefit.
 */

typedef struct _jobject      *jobject;
typedef struct _jclass       *jclass;
typedef struct _jstring      *jstring;
typedef struct _jthrowable   *jthrowable;
typedef struct _jarray       *jarray;
typedef struct _jbooleanArray *jbooleanArray;
typedef struct _jbyteArray   *jbyteArray;
typedef struct _jcharArray   *jcharArray;
typedef struct _jshortArray  *jshortArray;
typedef struct _jintArray    *jintArray;
typedef struct _jlongArray   *jlongArray;
typedef struct _jfloatArray  *jfloatArray;
typedef struct _jdoubleArray *jdoubleArray;
typedef struct _jobjectArray *jobjectArray;
typedef struct _jweak        *jweak;

typedef struct _jmethodID    *jmethodID;
typedef struct _jfieldID     *jfieldID;

typedef union jvalue {
    jboolean z;
    jbyte    b;
    jchar    c;
    jshort   s;
    jint     i;
    jlong    j;
    jfloat   f;
    jdouble  d;
    jobject  l;
} jvalue;

typedef enum _jobjectRefType {
    JNIInvalidRefType    = 0,
    JNILocalRefType      = 1,
    JNIGlobalRefType     = 2,
    JNIWeakGlobalRefType = 3
} jobjectRefType;

/* ------------------------------------------------------ dynamic registration
 *
 * THE struct. Three pointers per entry. A JNINativeMethod array in .rodata or
 * .data.rel.ro is what JNI_OnLoad hands to RegisterNatives, and applying this
 * type over that memory is how you turn an anonymous blob into a map from Java
 * method names to function addresses.
 *
 * sizeof(JNINativeMethod) == 24 on 64-bit, 12 on 32-bit.
 */

typedef struct {
    char *name;         /* e.g. "decrypt"                          */
    char *signature;    /* e.g. "(Ljava/lang/String;)Ljava/lang/String;" */
    void *fnPtr;        /* -> .text                                 */
} JNINativeMethod;

/* ------------------------------------------------------------- the VM table */

struct JNIInvokeInterface;
typedef const struct JNIInvokeInterface *JavaVM;

struct JNIInvokeInterface {
    void *reserved0;
    void *reserved1;
    void *reserved2;

    jint (*DestroyJavaVM)(JavaVM *vm);                              /* idx 3, 0x18 */
    jint (*AttachCurrentThread)(JavaVM *vm, void **penv, void *args);/* idx 4, 0x20 */
    jint (*DetachCurrentThread)(JavaVM *vm);                        /* idx 5, 0x28 */
    jint (*GetEnv)(JavaVM *vm, void **penv, jint version);          /* idx 6, 0x30 */
    jint (*AttachCurrentThreadAsDaemon)(JavaVM *vm, void **penv, void *args);
};

/* ------------------------------------------------------------ the env table
 *
 * The big one. Every JNI operation is an indirect call through this table.
 *
 * Reserved slots preserve the offsets of everything after them. Where a run of
 * functions is not declared, a `void *reservedN[k]` array occupies exactly k
 * slots so that the next named function lands at its true index.
 */

struct JNINativeInterface;
typedef const struct JNINativeInterface *JNIEnv;

struct JNINativeInterface {
    /* indices 0-3: reserved by the specification */
    void *reserved0;
    void *reserved1;
    void *reserved2;
    void *reserved3;

    jint    (*GetVersion)(JNIEnv *env);                                    /* 4   0x020 */
    jclass  (*DefineClass)(JNIEnv *env, const char *name, jobject loader,
                           const jbyte *buf, jsize len);                   /* 5   0x028 */
    jclass  (*FindClass)(JNIEnv *env, const char *name);                   /* 6   0x030 */

    jmethodID (*FromReflectedMethod)(JNIEnv *env, jobject method);         /* 7   0x038 */
    jfieldID  (*FromReflectedField)(JNIEnv *env, jobject field);           /* 8   0x040 */
    jobject   (*ToReflectedMethod)(JNIEnv *env, jclass cls,
                                   jmethodID methodID, jboolean isStatic); /* 9   0x048 */

    jclass  (*GetSuperclass)(JNIEnv *env, jclass sub);                     /* 10  0x050 */
    jboolean (*IsAssignableFrom)(JNIEnv *env, jclass sub, jclass sup);     /* 11  0x058 */
    jobject (*ToReflectedField)(JNIEnv *env, jclass cls, jfieldID fieldID,
                                jboolean isStatic);                        /* 12  0x060 */

    jint       (*Throw)(JNIEnv *env, jthrowable obj);                      /* 13  0x068 */
    jint       (*ThrowNew)(JNIEnv *env, jclass clazz, const char *msg);    /* 14  0x070 */
    jthrowable (*ExceptionOccurred)(JNIEnv *env);                          /* 15  0x078 */
    void       (*ExceptionDescribe)(JNIEnv *env);                          /* 16  0x080 */
    void       (*ExceptionClear)(JNIEnv *env);                             /* 17  0x088 */
    void       (*FatalError)(JNIEnv *env, const char *msg);                /* 18  0x090 */

    jint  (*PushLocalFrame)(JNIEnv *env, jint capacity);                   /* 19  0x098 */
    jobject (*PopLocalFrame)(JNIEnv *env, jobject result);                 /* 20  0x0a0 */

    jobject (*NewGlobalRef)(JNIEnv *env, jobject lobj);                    /* 21  0x0a8 */
    void    (*DeleteGlobalRef)(JNIEnv *env, jobject gref);                 /* 22  0x0b0 */
    void    (*DeleteLocalRef)(JNIEnv *env, jobject obj);                   /* 23  0x0b8 */
    jboolean (*IsSameObject)(JNIEnv *env, jobject obj1, jobject obj2);     /* 24  0x0c0 */
    jobject (*NewLocalRef)(JNIEnv *env, jobject ref);                      /* 25  0x0c8 */
    jint    (*EnsureLocalCapacity)(JNIEnv *env, jint capacity);            /* 26  0x0d0 */

    jobject (*AllocObject)(JNIEnv *env, jclass clazz);                     /* 27  0x0d8 */
    jobject (*NewObject)(JNIEnv *env, jclass clazz, jmethodID methodID, ...);/* 28 0x0e0 */
    void   *reserved29;                                                    /* 29  0x0e8 NewObjectV */
    jobject (*NewObjectA)(JNIEnv *env, jclass clazz, jmethodID methodID,
                          const jvalue *args);                             /* 30  0x0f0 */

    jclass    (*GetObjectClass)(JNIEnv *env, jobject obj);                 /* 31  0x0f8 */
    jboolean  (*IsInstanceOf)(JNIEnv *env, jobject obj, jclass clazz);     /* 32  0x100 */
    jmethodID (*GetMethodID)(JNIEnv *env, jclass clazz, const char *name,
                             const char *sig);                             /* 33  0x108 */

    jobject (*CallObjectMethod)(JNIEnv *env, jobject obj, jmethodID m, ...);/* 34 0x110 */
    void   *reserved35[2];                                                 /* 35-36 V, A */
    jboolean (*CallBooleanMethod)(JNIEnv *env, jobject obj, jmethodID m, ...);/* 37 0x128 */
    void   *reserved38[2];                                                 /* 38-39 */
    jbyte   (*CallByteMethod)(JNIEnv *env, jobject obj, jmethodID m, ...); /* 40  0x140 */
    void   *reserved41[2];                                                 /* 41-42 */
    jchar   (*CallCharMethod)(JNIEnv *env, jobject obj, jmethodID m, ...); /* 43  0x158 */
    void   *reserved44[2];                                                 /* 44-45 */
    jshort  (*CallShortMethod)(JNIEnv *env, jobject obj, jmethodID m, ...);/* 46  0x170 */
    void   *reserved47[2];                                                 /* 47-48 */
    jint    (*CallIntMethod)(JNIEnv *env, jobject obj, jmethodID m, ...);  /* 49  0x188 */
    void   *reserved50[2];                                                 /* 50-51 */
    jlong   (*CallLongMethod)(JNIEnv *env, jobject obj, jmethodID m, ...); /* 52  0x1a0 */
    void   *reserved53[2];                                                 /* 53-54 */
    jfloat  (*CallFloatMethod)(JNIEnv *env, jobject obj, jmethodID m, ...);/* 55  0x1b8 */
    void   *reserved56[2];                                                 /* 56-57 */
    jdouble (*CallDoubleMethod)(JNIEnv *env, jobject obj, jmethodID m, ...);/* 58 0x1d0 */
    void   *reserved59[2];                                                 /* 59-60 */
    void    (*CallVoidMethod)(JNIEnv *env, jobject obj, jmethodID m, ...); /* 61  0x1e8 */
    void   *reserved62[2];                                                 /* 62-63 */

    /* 64-112: CallNonvirtual*Method family (three variants each) */
    void   *reserved64[49];                                                /* 64-112 */

    jmethodID (*GetStaticMethodID)(JNIEnv *env, jclass clazz,
                                   const char *name, const char *sig);     /* 113 0x388 */

    jobject (*CallStaticObjectMethod)(JNIEnv *env, jclass c, jmethodID m, ...);/* 114 0x390 */
    void   *reserved115[2];
    jboolean (*CallStaticBooleanMethod)(JNIEnv *env, jclass c, jmethodID m, ...);/* 117 0x3a8 */
    void   *reserved118[2];
    jbyte   (*CallStaticByteMethod)(JNIEnv *env, jclass c, jmethodID m, ...);/* 120 0x3c0 */
    void   *reserved121[2];
    jchar   (*CallStaticCharMethod)(JNIEnv *env, jclass c, jmethodID m, ...);/* 123 0x3d8 */
    void   *reserved124[2];
    jshort  (*CallStaticShortMethod)(JNIEnv *env, jclass c, jmethodID m, ...);/* 126 0x3f0 */
    void   *reserved127[2];
    jint    (*CallStaticIntMethod)(JNIEnv *env, jclass c, jmethodID m, ...);/* 129 0x408 */
    void   *reserved130[2];
    jlong   (*CallStaticLongMethod)(JNIEnv *env, jclass c, jmethodID m, ...);/* 132 0x420 */
    void   *reserved133[2];
    jfloat  (*CallStaticFloatMethod)(JNIEnv *env, jclass c, jmethodID m, ...);/* 135 0x438 */
    void   *reserved136[2];
    jdouble (*CallStaticDoubleMethod)(JNIEnv *env, jclass c, jmethodID m, ...);/* 138 0x450 */
    void   *reserved139[2];
    void    (*CallStaticVoidMethod)(JNIEnv *env, jclass c, jmethodID m, ...);/* 141 0x468 */
    void   *reserved142[2];

    jfieldID (*GetStaticFieldID)(JNIEnv *env, jclass clazz,
                                 const char *name, const char *sig);       /* 144 0x480 */

    /* 145-152: GetStatic<Type>Field */
    jobject  (*GetStaticObjectField)(JNIEnv *env, jclass c, jfieldID f);   /* 145 0x488 */
    jboolean (*GetStaticBooleanField)(JNIEnv *env, jclass c, jfieldID f);  /* 146 0x490 */
    jbyte    (*GetStaticByteField)(JNIEnv *env, jclass c, jfieldID f);     /* 147 0x498 */
    jchar    (*GetStaticCharField)(JNIEnv *env, jclass c, jfieldID f);     /* 148 0x4a0 */
    jshort   (*GetStaticShortField)(JNIEnv *env, jclass c, jfieldID f);    /* 149 0x4a8 */
    jint     (*GetStaticIntField)(JNIEnv *env, jclass c, jfieldID f);      /* 150 0x4b0 */
    jlong    (*GetStaticLongField)(JNIEnv *env, jclass c, jfieldID f);     /* 151 0x4b8 */
    jfloat   (*GetStaticFloatField)(JNIEnv *env, jclass c, jfieldID f);    /* 152 0x4c0 */
    jdouble  (*GetStaticDoubleField)(JNIEnv *env, jclass c, jfieldID f);   /* 153 0x4c8 */

    /* 154-162: SetStatic<Type>Field */
    void   *reserved154[9];                                                /* 154-162 */

    jstring (*NewString)(JNIEnv *env, const jchar *unicode, jsize len);    /* 163 0x518 */
    jsize   (*GetStringLength)(JNIEnv *env, jstring str);                  /* 164 0x520 */
    const jchar *(*GetStringChars)(JNIEnv *env, jstring str, jboolean *c); /* 165 0x528 */
    void    (*ReleaseStringChars)(JNIEnv *env, jstring str, const jchar *c);/* 166 0x530 */

    /* THE TWO YOU WILL SEE MOST OFTEN */
    jstring (*NewStringUTF)(JNIEnv *env, const char *utf);                 /* 167 0x538 */
    jsize   (*GetStringUTFLength)(JNIEnv *env, jstring str);               /* 168 0x540 */
    const char *(*GetStringUTFChars)(JNIEnv *env, jstring str,
                                     jboolean *isCopy);                    /* 169 0x548 */
    void    (*ReleaseStringUTFChars)(JNIEnv *env, jstring str,
                                     const char *chars);                   /* 170 0x550 */

    jsize   (*GetArrayLength)(JNIEnv *env, jarray array);                  /* 171 0x558 */

    jobjectArray (*NewObjectArray)(JNIEnv *env, jsize len, jclass clazz,
                                   jobject init);                          /* 172 0x560 */
    jobject (*GetObjectArrayElement)(JNIEnv *env, jobjectArray a, jsize i);/* 173 0x568 */
    void    (*SetObjectArrayElement)(JNIEnv *env, jobjectArray a, jsize i,
                                     jobject val);                         /* 174 0x570 */

    jbooleanArray (*NewBooleanArray)(JNIEnv *env, jsize len);              /* 175 0x578 */
    jbyteArray    (*NewByteArray)(JNIEnv *env, jsize len);                 /* 176 0x580 */
    jcharArray    (*NewCharArray)(JNIEnv *env, jsize len);                 /* 177 0x588 */
    jshortArray   (*NewShortArray)(JNIEnv *env, jsize len);                /* 178 0x590 */
    jintArray     (*NewIntArray)(JNIEnv *env, jsize len);                  /* 179 0x598 */
    jlongArray    (*NewLongArray)(JNIEnv *env, jsize len);                 /* 180 0x5a0 */
    jfloatArray   (*NewFloatArray)(JNIEnv *env, jsize len);                /* 181 0x5a8 */
    jdoubleArray  (*NewDoubleArray)(JNIEnv *env, jsize len);               /* 182 0x5b0 */

    jboolean *(*GetBooleanArrayElements)(JNIEnv *env, jbooleanArray a,
                                         jboolean *isCopy);                /* 183 0x5b8 */
    jbyte    *(*GetByteArrayElements)(JNIEnv *env, jbyteArray a,
                                      jboolean *isCopy);                   /* 184 0x5c0 */
    jchar    *(*GetCharArrayElements)(JNIEnv *env, jcharArray a,
                                      jboolean *isCopy);                   /* 185 0x5c8 */
    jshort   *(*GetShortArrayElements)(JNIEnv *env, jshortArray a,
                                       jboolean *isCopy);                  /* 186 0x5d0 */
    jint     *(*GetIntArrayElements)(JNIEnv *env, jintArray a,
                                     jboolean *isCopy);                    /* 187 0x5d8 */
    jlong    *(*GetLongArrayElements)(JNIEnv *env, jlongArray a,
                                      jboolean *isCopy);                   /* 188 0x5e0 */
    jfloat   *(*GetFloatArrayElements)(JNIEnv *env, jfloatArray a,
                                       jboolean *isCopy);                  /* 189 0x5e8 */
    jdouble  *(*GetDoubleArrayElements)(JNIEnv *env, jdoubleArray a,
                                        jboolean *isCopy);                 /* 190 0x5f0 */

    void (*ReleaseBooleanArrayElements)(JNIEnv *env, jbooleanArray a,
                                        jboolean *elems, jint mode);       /* 191 0x5f8 */
    void (*ReleaseByteArrayElements)(JNIEnv *env, jbyteArray a,
                                     jbyte *elems, jint mode);             /* 192 0x600 */
    void *reserved193[6];                                                  /* 193-198 */

    void (*GetBooleanArrayRegion)(JNIEnv *env, jbooleanArray a, jsize s,
                                  jsize l, jboolean *buf);                 /* 199 0x638 */
    void (*GetByteArrayRegion)(JNIEnv *env, jbyteArray a, jsize s,
                               jsize l, jbyte *buf);                       /* 200 0x640 */
    void *reserved201[6];                                                  /* 201-206 */

    void (*SetBooleanArrayRegion)(JNIEnv *env, jbooleanArray a, jsize s,
                                  jsize l, const jboolean *buf);           /* 207 0x678 */
    void (*SetByteArrayRegion)(JNIEnv *env, jbyteArray a, jsize s,
                               jsize l, const jbyte *buf);                 /* 208 0x680 */
    void *reserved209[6];                                                  /* 209-214 */

    /* THE ONE THAT MATTERS FOR DYNAMIC REGISTRATION */
    jint (*RegisterNatives)(JNIEnv *env, jclass clazz,
                            const JNINativeMethod *methods, jint nMethods); /* 215 0x6b8 */
    jint (*UnregisterNatives)(JNIEnv *env, jclass clazz);                  /* 216 0x6c0 */

    jint (*MonitorEnter)(JNIEnv *env, jobject obj);                        /* 217 0x6c8 */
    jint (*MonitorExit)(JNIEnv *env, jobject obj);                         /* 218 0x6d0 */

    jint (*GetJavaVM)(JNIEnv *env, JavaVM **vm);                           /* 219 0x6d8 */

    void (*GetStringRegion)(JNIEnv *env, jstring str, jsize start,
                            jsize len, jchar *buf);                        /* 220 0x6e0 */
    void (*GetStringUTFRegion)(JNIEnv *env, jstring str, jsize start,
                               jsize len, char *buf);                      /* 221 0x6e8 */

    void *(*GetPrimitiveArrayCritical)(JNIEnv *env, jarray array,
                                       jboolean *isCopy);                  /* 222 0x6f0 */
    void  (*ReleasePrimitiveArrayCritical)(JNIEnv *env, jarray array,
                                           void *carray, jint mode);       /* 223 0x6f8 */

    const jchar *(*GetStringCritical)(JNIEnv *env, jstring s, jboolean *c); /* 224 0x700 */
    void  (*ReleaseStringCritical)(JNIEnv *env, jstring s, const jchar *c); /* 225 0x708 */

    jweak   (*NewWeakGlobalRef)(JNIEnv *env, jobject obj);                 /* 226 0x710 */
    void    (*DeleteWeakGlobalRef)(JNIEnv *env, jweak ref);                /* 227 0x718 */

    jboolean (*ExceptionCheck)(JNIEnv *env);                               /* 228 0x720 */

    jobject (*NewDirectByteBuffer)(JNIEnv *env, void *address, jlong cap);  /* 229 0x728 */
    void   *(*GetDirectBufferAddress)(JNIEnv *env, jobject buf);           /* 230 0x730 */
    jlong   (*GetDirectBufferCapacity)(JNIEnv *env, jobject buf);          /* 231 0x738 */

    jobjectRefType (*GetObjectRefType)(JNIEnv *env, jobject obj);          /* 232 0x740 */
};

/*
 * QUICK REFERENCE — the offsets you will actually recognise on sight,
 * for a 64-bit target:
 *
 *   0x030   FindClass                 which Java class native code reaches into
 *   0x0a8   NewGlobalRef              caching a class or object for later
 *   0x0f8   GetObjectClass            the class of `thiz`
 *   0x108   GetMethodID               PAIRED with a name and signature string
 *   0x388   GetStaticMethodID         same, static
 *   0x538   NewStringUTF              native producing a Java string
 *   0x548   GetStringUTFChars         native consuming a Java string
 *   0x550   ReleaseStringUTFChars     pairs with the above
 *   0x558   GetArrayLength            a length check on an input
 *   0x580   NewByteArray              producing a result buffer
 *   0x5c0   GetByteArrayElements      crypto input
 *   0x600   ReleaseByteArrayElements  pairs with the above
 *   0x680   SetByteArrayRegion        writing the result back
 *   0x6b8   RegisterNatives           THE dynamic registration table
 *   0x6d8   GetJavaVM                 caching the VM for thread attachment
 *
 * For a 32-bit target, divide every index by 2:  RegisterNatives is 0x35c.
 */
