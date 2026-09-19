#include "vm/pvm2_interp.h"
#include "vm/pvm2_format.h"
#include "common/runtime_state.h"
#include "common/log.h"
#include "common/protector_macro.h"
#include "crypto/aes.h"
#include "risk/risk.h"
#include "risk/so_guard.h"

#include <atomic>
#include <cmath>
#include <cstring>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace protector::vm {

struct Reg {
    int32_t i = 0;
    int64_t j = 0;
    jobject o = nullptr;
    /** RK_I / RK_J / RK_L — Dalvik if-eqz on objects must use .o, not leftover .i. */
    uint8_t k = 0;
    /** When true, o is a GlobalRef (OEM NewLocalRef alias fallback). */
    bool o_global = false;
};

enum : uint8_t {
    RK_I = 0,
    RK_J = 1,
    RK_L = 2,
};

struct PendingResult {
    bool valid = false;
    int32_t i = 0;
    int64_t j = 0;
    jobject o = nullptr;
    uint8_t k = RK_I;
    bool o_global = false;
};

/** Active interpret frame — used to scrub aliased jobject cookies before Delete*. */
struct InterpFrame {
    std::vector<Reg>* regs = nullptr;
    PendingResult* pending = nullptr;
    jobject* stashed_exception = nullptr;
    /** Outer interpret on this thread (nested VMP via Call* → VmBridge). */
    InterpFrame* prev = nullptr;
};

static thread_local InterpFrame* g_interp_frame = nullptr;

struct InterpFrameScope {
    InterpFrame frame;
    InterpFrameScope(std::vector<Reg>& regs, PendingResult& pending, jobject* stashed) {
        frame.regs = &regs;
        frame.pending = &pending;
        frame.stashed_exception = stashed;
        frame.prev = g_interp_frame;
        g_interp_frame = &frame;
    }
    ~InterpFrameScope() { g_interp_frame = frame.prev; }
};

static void scrub_one_frame(InterpFrame* f, jobject o) {
    if (f == nullptr || o == nullptr) {
        return;
    }
    if (f->regs != nullptr) {
        for (auto& r : *f->regs) {
            if (r.o == o) {
                r.o = nullptr;
                r.o_global = false;
            }
        }
    }
    if (f->pending != nullptr && f->pending->o == o) {
        f->pending->o = nullptr;
        f->pending->o_global = false;
    }
    if (f->stashed_exception != nullptr && *f->stashed_exception == o) {
        *f->stashed_exception = nullptr;
    }
}

/** Null every slot that holds cookie o across this + outer nested interpret frames. */
static void scrub_ref_aliases(jobject o) {
    if (o == nullptr) {
        return;
    }
    for (InterpFrame* f = g_interp_frame; f != nullptr; f = f->prev) {
        scrub_one_frame(f, o);
    }
}

static void release_ref(JNIEnv* env, jobject o, bool is_global) {
    if (o == nullptr) {
        return;
    }
    scrub_ref_aliases(o);
    if (is_global) {
        env->DeleteGlobalRef(o);
    } else {
        env->DeleteLocalRef(o);
    }
}

static void release_stash(JNIEnv* env, jobject* stashed) {
    if (stashed == nullptr || *stashed == nullptr) {
        return;
    }
    jobject o = *stashed;
    *stashed = nullptr;
    release_ref(env, o, false);
}

/**
 * Copy a reference into a distinct JNI handle for register ownership.
 * On OEM ART, NewLocalRef(local) may return the same cookie — fall back to GlobalRef
 * so move-object / arg copies do not share a deletable Local slot.
 */
static jobject dup_owned_ref(JNIEnv* env, jobject src, bool* out_global) {
    *out_global = false;
    if (src == nullptr) {
        return nullptr;
    }
    jobject local = env->NewLocalRef(src);
    if (local != nullptr && local != src) {
        return local;
    }
    jobject global = env->NewGlobalRef(src);
    if (global != nullptr) {
        *out_global = true;
        return global;
    }
    // Last resort: keep whatever NewLocalRef gave (may alias src).
    return local != nullptr ? local : src;
}

/** Promote GlobalRef to a Local for stash / Throw; deletes Global only on success. */
static jobject global_to_local(JNIEnv* env, jobject global) {
    if (global == nullptr) {
        return nullptr;
    }
    jobject local = env->NewLocalRef(global);
    if (local == nullptr) {
        return nullptr;  // keep Global so caller can retry or release_ref
    }
    env->DeleteGlobalRef(global);
    return local;
}

static void throw_arith(JNIEnv* env, const char* msg);
static void throw_runtime(JNIEnv* env, const char* msg);
static void throw_npe(JNIEnv* env, const char* msg);
static void throw_cce(JNIEnv* env, const char* msg);
static void throw_security(JNIEnv* env, const char* msg);
static bool ensure_well_known_classes(JNIEnv* env);

static int16_t read_i16(const uint8_t* p) {
    int16_t v;
    memcpy(&v, p, 2);
    return v;
}

static int32_t read_i32(const uint8_t* p) {
    int32_t v;
    memcpy(&v, p, 4);
    return v;
}

static int64_t read_i64(const uint8_t* p) {
    int64_t v;
    memcpy(&v, p, 8);
    return v;
}

static int64_t imm_key64(int32_t key) {
    uint32_t k = static_cast<uint32_t>(key);
    return static_cast<int64_t>((static_cast<uint64_t>(k) << 32) | k);
}

static uint16_t read_u16(const uint8_t* p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static bool cmp_i32(int cond, int32_t a, int32_t b) {
    switch (cond) {
        case COND_EQ: return a == b;
        case COND_NE: return a != b;
        case COND_LT: return a < b;
        case COND_GE: return a >= b;
        case COND_GT: return a > b;
        case COND_LE: return a <= b;
        default: return false;
    }
}

static void reg_drop_obj(JNIEnv* env, Reg* r) {
    jobject o = r->o;
    if (o == nullptr) {
        return;
    }
    bool g = r->o_global;
    r->o = nullptr;
    r->o_global = false;
    release_ref(env, o, g);
}

static void reg_as_i(JNIEnv* env, Reg* r) {
    reg_drop_obj(env, r);
    r->k = RK_I;
}

static void reg_as_j(JNIEnv* env, Reg* r) {
    reg_drop_obj(env, r);
    r->k = RK_J;
}

/** Take ownership of jobject into register (object kind). */
static void reg_take_o(JNIEnv* env, Reg* r, jobject o, bool o_global = false) {
    jobject old = r->o;
    bool old_global = r->o_global;
    r->o = o;
    r->o_global = o_global;
    r->i = 0;
    r->k = RK_L;
    if (old != nullptr && old != o) {
        release_ref(env, old, old_global);
    }
}

/** if-eqz / if-nez: objects use nullness of .o; ints use .i. */
static bool eval_if_z(int cond, const Reg& a) {
    if (a.k == RK_L) {
        if (cond == COND_EQ) {
            return a.o == nullptr;
        }
        if (cond == COND_NE) {
            return a.o != nullptr;
        }
        return false;
    }
    return cmp_i32(cond, a.i, 0);
}

/** if-eq / if-ne on refs → IsSameObject; relational ops stay int-only. */
static bool eval_if_cmp(JNIEnv* env, int cond, const Reg& a, const Reg& b) {
    if (a.k == RK_L || b.k == RK_L) {
        if (cond == COND_EQ) {
            return env->IsSameObject(a.o, b.o) == JNI_TRUE;
        }
        if (cond == COND_NE) {
            return env->IsSameObject(a.o, b.o) != JNI_TRUE;
        }
        return false;
    }
    return cmp_i32(cond, a.i, b.i);
}

static bool binop_i32(JNIEnv* env, int op, int32_t a, int32_t b, int32_t* out) {
    switch (op) {
        case BIN_ADD: *out = a + b; return true;
        case BIN_SUB: *out = a - b; return true;
        case BIN_MUL: *out = a * b; return true;
        case BIN_AND: *out = a & b; return true;
        case BIN_OR: *out = a | b; return true;
        case BIN_XOR: *out = a ^ b; return true;
        case BIN_SHL: *out = a << (b & 31); return true;
        case BIN_SHR: *out = a >> (b & 31); return true;
        case BIN_USHR:
            *out = static_cast<int32_t>(static_cast<uint32_t>(a) >> (b & 31));
            return true;
        case BIN_DIV:
            if (b == 0) {
                throw_arith(env, "/ by zero");
                return false;
            }
            // Dalvik: INT_MIN / -1 == INT_MIN
            if (a == static_cast<int32_t>(0x80000000) && b == -1) {
                *out = a;
                return true;
            }
            *out = a / b;
            return true;
        case BIN_REM:
            if (b == 0) {
                throw_arith(env, "/ by zero");
                return false;
            }
            if (a == static_cast<int32_t>(0x80000000) && b == -1) {
                *out = 0;
                return true;
            }
            *out = a % b;
            return true;
        default:
            *out = 0;
            return true;
    }
}

static bool binop_i64(JNIEnv* env, int op, int64_t a, int64_t b, int64_t* out) {
    switch (op) {
        case BIN_ADD: *out = a + b; return true;
        case BIN_SUB: *out = a - b; return true;
        case BIN_MUL: *out = a * b; return true;
        case BIN_AND: *out = a & b; return true;
        case BIN_OR: *out = a | b; return true;
        case BIN_XOR: *out = a ^ b; return true;
        case BIN_SHL: *out = a << (b & 63); return true;
        case BIN_SHR: *out = a >> (b & 63); return true;
        case BIN_USHR:
            *out = static_cast<int64_t>(static_cast<uint64_t>(a) >> (b & 63));
            return true;
        case BIN_DIV:
            if (b == 0) {
                throw_arith(env, "/ by zero");
                return false;
            }
            if (a == std::numeric_limits<int64_t>::min() && b == -1) {
                *out = a;
                return true;
            }
            *out = a / b;
            return true;
        case BIN_REM:
            if (b == 0) {
                throw_arith(env, "/ by zero");
                return false;
            }
            if (a == std::numeric_limits<int64_t>::min() && b == -1) {
                *out = 0;
                return true;
            }
            *out = a % b;
            return true;
        default:
            *out = 0;
            return true;
    }
}

static float as_float(int32_t bits) {
    float f;
    memcpy(&f, &bits, sizeof(f));
    return f;
}

static int32_t float_bits(float f) {
    int32_t bits;
    memcpy(&bits, &f, sizeof(bits));
    return bits;
}

static double as_double(int64_t bits) {
    double d;
    memcpy(&d, &bits, sizeof(d));
    return d;
}

/** ART/Dalvik float→int: NaN→0, clamp to INT_MIN/MAX. */
static int32_t art_float_to_int(float f) {
    if (std::isnan(f)) {
        return 0;
    }
    if (f >= static_cast<float>(std::numeric_limits<int32_t>::max())) {
        return std::numeric_limits<int32_t>::max();
    }
    if (f <= static_cast<float>(std::numeric_limits<int32_t>::min())) {
        return std::numeric_limits<int32_t>::min();
    }
    return static_cast<int32_t>(f);
}

/** ART/Dalvik float→long: NaN→0, clamp to LONG_MIN/MAX. */
static int64_t art_float_to_long(float f) {
    if (std::isnan(f)) {
        return 0;
    }
    if (f >= static_cast<float>(std::numeric_limits<int64_t>::max())) {
        return std::numeric_limits<int64_t>::max();
    }
    if (f <= static_cast<float>(std::numeric_limits<int64_t>::min())) {
        return std::numeric_limits<int64_t>::min();
    }
    return static_cast<int64_t>(f);
}

static int32_t art_double_to_int(double d) {
    if (std::isnan(d)) {
        return 0;
    }
    if (d >= static_cast<double>(std::numeric_limits<int32_t>::max())) {
        return std::numeric_limits<int32_t>::max();
    }
    if (d <= static_cast<double>(std::numeric_limits<int32_t>::min())) {
        return std::numeric_limits<int32_t>::min();
    }
    return static_cast<int32_t>(d);
}

static int64_t art_double_to_long(double d) {
    if (std::isnan(d)) {
        return 0;
    }
    if (d >= static_cast<double>(std::numeric_limits<int64_t>::max())) {
        return std::numeric_limits<int64_t>::max();
    }
    if (d <= static_cast<double>(std::numeric_limits<int64_t>::min())) {
        return std::numeric_limits<int64_t>::min();
    }
    return static_cast<int64_t>(d);
}

static bool is_shift_binop(int bin) {
    return bin == BIN_SHL || bin == BIN_SHR || bin == BIN_USHR;
}

static int64_t double_bits(double d) {
    int64_t bits;
    memcpy(&bits, &d, sizeof(bits));
    return bits;
}

static float binop_f32(int op, float a, float b) {
    switch (op) {
        case BIN_ADD: return a + b;
        case BIN_SUB: return a - b;
        case BIN_MUL: return a * b;
        case BIN_DIV: return a / b;
        case BIN_REM: return std::fmod(a, b);
        default: return 0.0f;
    }
}

static double binop_f64(int op, double a, double b) {
    switch (op) {
        case BIN_ADD: return a + b;
        case BIN_SUB: return a - b;
        case BIN_MUL: return a * b;
        case BIN_DIV: return a / b;
        case BIN_REM: return std::fmod(a, b);
        default: return 0.0;
    }
}

static int32_t cmp_float(float a, float b, bool nan_gt) {
    if (a == b) return 0;
    if (a < b) return -1;
    if (a > b) return 1;
    return nan_gt ? 1 : -1;
}

static int32_t cmp_double(double a, double b, bool nan_gt) {
    if (a == b) return 0;
    if (a < b) return -1;
    if (a > b) return 1;
    return nan_gt ? 1 : -1;
}

static int32_t cmp_long(int64_t a, int64_t b) {
    if (a == b) return 0;
    return (a < b) ? -1 : 1;
}

static bool apply_unop(int kind, Reg* dst, const Reg& src) {
    switch (kind) {
        case UN_NEG_LONG:
            dst->j = -src.j;
            return true;
        case UN_NEG_FLOAT:
            dst->i = float_bits(-as_float(src.i));
            return true;
        case UN_NEG_DOUBLE:
            dst->j = double_bits(-as_double(src.j));
            return true;
        case UN_NOT_INT:
            dst->i = ~src.i;
            return true;
        case UN_NOT_LONG:
            dst->j = ~src.j;
            return true;
        case UN_INT_TO_LONG:
            dst->j = static_cast<int64_t>(src.i);
            return true;
        case UN_INT_TO_FLOAT:
            dst->i = float_bits(static_cast<float>(src.i));
            return true;
        case UN_INT_TO_DOUBLE:
            dst->j = double_bits(static_cast<double>(src.i));
            return true;
        case UN_LONG_TO_INT:
            dst->i = static_cast<int32_t>(src.j);
            return true;
        case UN_LONG_TO_FLOAT:
            dst->i = float_bits(static_cast<float>(src.j));
            return true;
        case UN_LONG_TO_DOUBLE:
            dst->j = double_bits(static_cast<double>(src.j));
            return true;
        case UN_FLOAT_TO_INT:
            dst->i = art_float_to_int(as_float(src.i));
            return true;
        case UN_FLOAT_TO_LONG:
            dst->j = art_float_to_long(as_float(src.i));
            return true;
        case UN_FLOAT_TO_DOUBLE:
            dst->j = double_bits(static_cast<double>(as_float(src.i)));
            return true;
        case UN_DOUBLE_TO_INT:
            dst->i = art_double_to_int(as_double(src.j));
            return true;
        case UN_DOUBLE_TO_LONG:
            dst->j = art_double_to_long(as_double(src.j));
            return true;
        case UN_DOUBLE_TO_FLOAT:
            dst->i = float_bits(static_cast<float>(as_double(src.j)));
            return true;
        case UN_INT_TO_BYTE:
            dst->i = static_cast<int8_t>(src.i);
            return true;
        case UN_INT_TO_CHAR:
            dst->i = static_cast<uint16_t>(src.i);
            return true;
        case UN_INT_TO_SHORT:
            dst->i = static_cast<int16_t>(src.i);
            return true;
        default:
            return false;
    }
}

static void clear_regs(JNIEnv* env, std::vector<Reg>& regs) {
    // Dedup before Delete*: move-object / OEM NewLocalRef may leave the same
    // jobject cookie in multiple regs; deleting twice aborts with "stale Local".
    // scrub_ref_aliases also clears outer nested interpret frames.
    for (size_t i = 0; i < regs.size(); ++i) {
        jobject o = regs[i].o;
        if (o == nullptr) {
            continue;
        }
        bool g = regs[i].o_global;
        regs[i].o = nullptr;
        regs[i].o_global = false;
        for (size_t j = i + 1; j < regs.size(); ++j) {
            if (regs[j].o == o) {
                regs[j].o = nullptr;
                regs[j].o_global = false;
            }
        }
        scrub_ref_aliases(o);
        if (g) {
            env->DeleteGlobalRef(o);
        } else {
            env->DeleteLocalRef(o);
        }
    }
}

static void clear_pending(JNIEnv* env, PendingResult& pending) {
    if (pending.o != nullptr) {
        jobject o = pending.o;
        bool g = pending.o_global;
        pending.o = nullptr;
        pending.o_global = false;
        release_ref(env, o, g);
    }
    pending.valid = false;
    pending.k = RK_I;
}

static std::string descriptor_to_jni(const std::string& desc) {
    if (desc.size() >= 2 && desc[0] == 'L' && desc.back() == ';') {
        return desc.substr(1, desc.size() - 2);
    }
    return desc;
}

// ---------------------------------------------------------------------------
// JNI Local / Global management (L1 ownership + L2 frames + L3 capacity/cache)
// ---------------------------------------------------------------------------

/** RAII PushLocalFrame. pop(result) promotes a local out; otherwise dtor discards. */
struct JniLocalFrame {
    JNIEnv* env = nullptr;
    bool active = false;

    JniLocalFrame(JNIEnv* e, jint capacity) : env(e) {
        if (env != nullptr && env->PushLocalFrame(capacity) == 0) {
            active = true;
        }
    }

    jobject pop(jobject result) {
        if (!active) {
            return result;
        }
        active = false;
        return env->PopLocalFrame(result);
    }

    ~JniLocalFrame() {
        if (active) {
            env->PopLocalFrame(nullptr);
        }
    }

    JniLocalFrame(const JniLocalFrame&) = delete;
    JniLocalFrame& operator=(const JniLocalFrame&) = delete;
};

struct JniClassCache {
    std::mutex mu;
    std::unordered_map<std::string, jclass> by_name;  // GlobalRef values

    jclass arithmetic_ex = nullptr;
    jclass runtime_ex = nullptr;
    jclass npe = nullptr;
    jclass cce = nullptr;
    jclass security_ex = nullptr;
    jclass integer_cls = nullptr;
    jclass long_cls = nullptr;
    jclass boolean_cls = nullptr;
    jclass float_cls = nullptr;
    jclass double_cls = nullptr;
    jclass float_arr = nullptr;
    jclass double_arr = nullptr;
    jclass bool_arr = nullptr;
    jclass char_arr = nullptr;

    jmethodID integer_valueOf = nullptr;
    jmethodID long_valueOf = nullptr;
    jmethodID boolean_valueOf = nullptr;
    jmethodID float_valueOf = nullptr;
    jmethodID double_valueOf = nullptr;
    jmethodID integer_intValue = nullptr;
    jmethodID long_longValue = nullptr;
    jmethodID boolean_booleanValue = nullptr;
    jmethodID float_floatValue = nullptr;
    jmethodID double_doubleValue = nullptr;

    std::atomic<bool> well_known_ready{false};
};

static JniClassCache& jni_cache() {
    static JniClassCache cache;
    return cache;
}

/** Cache FindClass as GlobalRef. Returned jclass must NOT be DeleteLocalRef'd. */
static jclass cache_global_class(JNIEnv* env, const char* jni_name) {
    if (env == nullptr || jni_name == nullptr) {
        return nullptr;
    }
    auto& cache = jni_cache();
    {
        std::lock_guard<std::mutex> lock(cache.mu);
        auto it = cache.by_name.find(jni_name);
        if (it != cache.by_name.end()) {
            return it->second;
        }
    }
    jclass local = env->FindClass(jni_name);
    if (local == nullptr) {
        return nullptr;
    }
    jclass global = reinterpret_cast<jclass>(env->NewGlobalRef(local));
    env->DeleteLocalRef(local);
    if (global == nullptr) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(cache.mu);
    auto it = cache.by_name.find(jni_name);
    if (it != cache.by_name.end()) {
        env->DeleteGlobalRef(global);
        return it->second;
    }
    cache.by_name.emplace(jni_name, global);
    return global;
}

static bool ensure_well_known_classes(JNIEnv* env) {
    auto& c = jni_cache();
    if (c.well_known_ready.load(std::memory_order_acquire)) {
        return true;
    }

    // Resolve classes WITHOUT holding c.mu — FindClass may re-enter app code.
    jclass arithmetic_ex = cache_global_class(env, "java/lang/ArithmeticException");
    jclass runtime_ex = cache_global_class(env, "java/lang/RuntimeException");
    jclass npe = cache_global_class(env, "java/lang/NullPointerException");
    jclass cce = cache_global_class(env, "java/lang/ClassCastException");
    jclass security_ex = cache_global_class(env, "java/lang/SecurityException");
    jclass integer_cls = cache_global_class(env, "java/lang/Integer");
    jclass long_cls = cache_global_class(env, "java/lang/Long");
    jclass boolean_cls = cache_global_class(env, "java/lang/Boolean");
    jclass float_cls = cache_global_class(env, "java/lang/Float");
    jclass double_cls = cache_global_class(env, "java/lang/Double");
    jclass float_arr = cache_global_class(env, "[F");
    jclass double_arr = cache_global_class(env, "[D");
    jclass bool_arr = cache_global_class(env, "[Z");
    jclass char_arr = cache_global_class(env, "[C");

    if (integer_cls == nullptr || long_cls == nullptr || boolean_cls == nullptr
            || float_cls == nullptr || double_cls == nullptr
            || arithmetic_ex == nullptr || runtime_ex == nullptr
            || npe == nullptr || cce == nullptr || security_ex == nullptr) {
        return false;
    }

    jmethodID integer_valueOf = env->GetStaticMethodID(integer_cls, "valueOf", "(I)Ljava/lang/Integer;");
    jmethodID long_valueOf = env->GetStaticMethodID(long_cls, "valueOf", "(J)Ljava/lang/Long;");
    jmethodID boolean_valueOf = env->GetStaticMethodID(boolean_cls, "valueOf", "(Z)Ljava/lang/Boolean;");
    jmethodID float_valueOf = env->GetStaticMethodID(float_cls, "valueOf", "(F)Ljava/lang/Float;");
    jmethodID double_valueOf = env->GetStaticMethodID(double_cls, "valueOf", "(D)Ljava/lang/Double;");
    jmethodID integer_intValue = env->GetMethodID(integer_cls, "intValue", "()I");
    jmethodID long_longValue = env->GetMethodID(long_cls, "longValue", "()J");
    jmethodID boolean_booleanValue = env->GetMethodID(boolean_cls, "booleanValue", "()Z");
    jmethodID float_floatValue = env->GetMethodID(float_cls, "floatValue", "()F");
    jmethodID double_doubleValue = env->GetMethodID(double_cls, "doubleValue", "()D");

    if (integer_valueOf == nullptr || long_valueOf == nullptr || boolean_valueOf == nullptr
            || float_valueOf == nullptr || double_valueOf == nullptr
            || integer_intValue == nullptr || long_longValue == nullptr
            || boolean_booleanValue == nullptr || float_floatValue == nullptr
            || double_doubleValue == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> lock(c.mu);
    if (c.well_known_ready.load(std::memory_order_relaxed)) {
        return true;
    }
    c.arithmetic_ex = arithmetic_ex;
    c.runtime_ex = runtime_ex;
    c.npe = npe;
    c.cce = cce;
    c.security_ex = security_ex;
    c.integer_cls = integer_cls;
    c.long_cls = long_cls;
    c.boolean_cls = boolean_cls;
    c.float_cls = float_cls;
    c.double_cls = double_cls;
    c.float_arr = float_arr;
    c.double_arr = double_arr;
    c.bool_arr = bool_arr;
    c.char_arr = char_arr;
    c.integer_valueOf = integer_valueOf;
    c.long_valueOf = long_valueOf;
    c.boolean_valueOf = boolean_valueOf;
    c.float_valueOf = float_valueOf;
    c.double_valueOf = double_valueOf;
    c.integer_intValue = integer_intValue;
    c.long_longValue = long_longValue;
    c.boolean_booleanValue = boolean_booleanValue;
    c.float_floatValue = float_floatValue;
    c.double_doubleValue = double_doubleValue;
    c.well_known_ready.store(true, std::memory_order_release);
    return true;
}

/** Descriptor or internal name → GlobalRef jclass. Do NOT DeleteLocalRef. */
static jclass find_class_desc(JNIEnv* env, const std::string& desc) {
    return cache_global_class(env, descriptor_to_jni(desc).c_str());
}

static jclass find_jni_class(JNIEnv* env, const char* jni_name) {
    return cache_global_class(env, jni_name);
}

static void throw_cached(JNIEnv* env, jclass ex_cls, const char* msg) {
    if (ex_cls != nullptr) {
        env->ThrowNew(ex_cls, msg);
        return;
    }
    jclass local = env->FindClass("java/lang/RuntimeException");
    if (local != nullptr) {
        env->ThrowNew(local, msg != nullptr ? msg : "VMP error");
        env->DeleteLocalRef(local);
    }
}

static void throw_arith(JNIEnv* env, const char* msg) {
    throw_cached(env, jni_cache().arithmetic_ex, msg);
}

static void throw_runtime(JNIEnv* env, const char* msg) {
    throw_cached(env, jni_cache().runtime_ex, msg);
}

static void throw_npe(JNIEnv* env, const char* msg) {
    throw_cached(env, jni_cache().npe, msg);
}

static void throw_cce(JNIEnv* env, const char* msg) {
    throw_cached(env, jni_cache().cce, msg);
}

static void throw_security(JNIEnv* env, const char* msg) {
    throw_cached(env, jni_cache().security_ex, msg);
}

static bool parse_member_ref(const std::string& s, std::string* owner,
                             std::string* name, std::string* tail) {
    if (owner == nullptr || name == nullptr || tail == nullptr) {
        return false;
    }
    auto arrow = s.find("->");
    if (arrow == std::string::npos) {
        return false;
    }
    *owner = s.substr(0, arrow);
    auto split = s.find_first_of(":(", arrow + 2);
    if (split == std::string::npos) {
        return false;
    }
    *name = s.substr(arrow + 2, split - arrow - 2);
    *tail = s.substr(split);
    return true;
}

static std::vector<char> parse_arg_types(const char* sig) {
    std::vector<char> out;
    if (sig == nullptr || sig[0] != '(') {
        return out;
    }
    const char* p = sig + 1;
    while (*p && *p != ')') {
        if (*p == 'L') {
            while (*p && *p != ';') {
                p++;
            }
            if (*p == ';') {
                p++;
            }
            out.push_back('L');
        } else if (*p == '[') {
            while (*p == '[') {
                p++;
            }
            if (*p == 'L') {
                while (*p && *p != ';') {
                    p++;
                }
                if (*p == ';') {
                    p++;
                }
            } else if (*p != '\0') {
                p++;
            }
            out.push_back('L');
        } else {
            out.push_back(*p++);
        }
    }
    return out;
}

static const char* return_type_of_sig(const char* sig) {
    if (sig == nullptr) {
        return "V";
    }
    const char* p = strchr(sig, ')');
    return (p != nullptr && p[1] != '\0') ? p + 1 : "V";
}

static bool reg_bounds(uint8_t r, size_t reg_count) {
    return r < reg_count;
}

static bool reg_bounds_wide(uint8_t r, size_t reg_count) {
    return r + 1 < reg_count;
}

static jobject box_int(JNIEnv* env, int32_t v) {
    auto& c = jni_cache();
    if (!ensure_well_known_classes(env)) return nullptr;
    return env->CallStaticObjectMethod(c.integer_cls, c.integer_valueOf, v);
}

static jobject box_long(JNIEnv* env, int64_t v) {
    auto& c = jni_cache();
    if (!ensure_well_known_classes(env)) return nullptr;
    return env->CallStaticObjectMethod(c.long_cls, c.long_valueOf, v);
}

static jobject box_bool(JNIEnv* env, bool v) {
    auto& c = jni_cache();
    if (!ensure_well_known_classes(env)) return nullptr;
    return env->CallStaticObjectMethod(c.boolean_cls, c.boolean_valueOf, v ? JNI_TRUE : JNI_FALSE);
}

static jobject box_float(JNIEnv* env, jfloat v) {
    auto& c = jni_cache();
    if (!ensure_well_known_classes(env)) return nullptr;
    return env->CallStaticObjectMethod(c.float_cls, c.float_valueOf, v);
}

static jobject box_double(JNIEnv* env, jdouble v) {
    auto& c = jni_cache();
    if (!ensure_well_known_classes(env)) return nullptr;
    return env->CallStaticObjectMethod(c.double_cls, c.double_valueOf, v);
}

static bool unbox_arg(JNIEnv* env, jobject obj, const char* expected, Reg* out) {
    if (expected[0] == 'L' || expected[0] == '[') {
        bool g = false;
        jobject copy = obj ? dup_owned_ref(env, obj, &g) : nullptr;
        reg_take_o(env, out, copy, g);
        return true;
    }
    if (obj == nullptr) {
        return false;
    }
    if (!ensure_well_known_classes(env)) {
        return false;
    }
    auto& c = jni_cache();
    switch (expected[0]) {
        case 'I':
        case 'B':
        case 'S':
        case 'C': {
            reg_as_i(env, out);
            out->i = env->CallIntMethod(obj, c.integer_intValue);
            return !env->ExceptionCheck();
        }
        case 'Z': {
            reg_as_i(env, out);
            out->i = env->CallBooleanMethod(obj, c.boolean_booleanValue) ? 1 : 0;
            return !env->ExceptionCheck();
        }
        case 'J': {
            reg_as_j(env, out);
            out->j = env->CallLongMethod(obj, c.long_longValue);
            return !env->ExceptionCheck();
        }
        case 'F': {
            jfloat f = env->CallFloatMethod(obj, c.float_floatValue);
            if (env->ExceptionCheck()) return false;
            reg_as_i(env, out);
            memcpy(&out->i, &f, sizeof(f));
            return true;
        }
        case 'D': {
            jdouble d = env->CallDoubleMethod(obj, c.double_doubleValue);
            if (env->ExceptionCheck()) return false;
            reg_as_j(env, out);
            memcpy(&out->j, &d, sizeof(d));
            return true;
        }
        default:
            return false;
    }
}

static bool fill_jargs(const char* sig, const uint8_t* arg_regs, uint8_t argc,
                       const std::vector<Reg>& regs, jvalue* jargs, int* logical_argc) {
    std::vector<char> types = parse_arg_types(sig);
    int ti = 0;
    int ri = 0;
    while (ri < argc) {
        if (ti >= static_cast<int>(types.size())) {
            return false;
        }
        char t = types[ti++];
        uint8_t r = arg_regs[ri];
        if (!reg_bounds(r, regs.size())) {
            return false;
        }
        switch (t) {
            case 'Z':
                jargs[ti - 1].z = regs[r].i != 0 ? JNI_TRUE : JNI_FALSE;
                ri += 1;
                break;
            case 'B':
                jargs[ti - 1].b = static_cast<jbyte>(regs[r].i);
                ri += 1;
                break;
            case 'S':
                jargs[ti - 1].s = static_cast<jshort>(regs[r].i);
                ri += 1;
                break;
            case 'C':
                jargs[ti - 1].c = static_cast<jchar>(regs[r].i);
                ri += 1;
                break;
            case 'I':
                jargs[ti - 1].i = regs[r].i;
                ri += 1;
                break;
            case 'F': {
                jfloat f;
                memcpy(&f, &regs[r].i, sizeof(f));
                jargs[ti - 1].f = f;
                ri += 1;
                break;
            }
            case 'J':
                if (!reg_bounds_wide(r, regs.size())) {
                    return false;
                }
                jargs[ti - 1].j = regs[r].j;
                ri += 2;
                break;
            case 'D': {
                if (!reg_bounds_wide(r, regs.size())) {
                    return false;
                }
                jdouble d;
                memcpy(&d, &regs[r].j, sizeof(d));
                jargs[ti - 1].d = d;
                ri += 2;
                break;
            }
            default:
                jargs[ti - 1].l = regs[r].o;
                ri += 1;
                break;
        }
    }
    if (ri != argc || ti != static_cast<int>(types.size())) {
        return false;
    }
    if (logical_argc) {
        *logical_argc = ti;
    }
    return true;
}

static bool invoke_method(JNIEnv* env, uint8_t op, const std::string& desc,
                          const uint8_t* arg_regs, uint8_t argc,
                          const std::vector<Reg>& regs, PendingResult& pending) {
    // Outer locals (pending/regs) must be DeleteLocalRef'd ONLY while no inner
    // PushLocalFrame is active — otherwise ART reports
    // "Attempt to remove index outside index area" / DeleteLocalRef failed.
    clear_pending(env, pending);

    std::string owner;
    std::string name;
    std::string sig;
    if (!parse_member_ref(desc, &owner, &name, &sig)) {
        return false;
    }
    jclass cls = find_class_desc(env, owner);
    if (cls == nullptr) {
        return false;
    }
    jmethodID mid = (op == OP_INVOKE_STATIC)
            ? env->GetStaticMethodID(cls, name.c_str(), sig.c_str())
            : env->GetMethodID(cls, name.c_str(), sig.c_str());
    if (mid == nullptr) {
        return false;
    }

    const uint8_t* param_regs = arg_regs;
    uint8_t param_regc = argc;
    jobject thiz = nullptr;
    if (op != OP_INVOKE_STATIC) {
        if (argc == 0) {
            throw_runtime(env, "VMP invoke missing receiver");
            return false;
        }
        uint8_t recv = arg_regs[0];
        if (!reg_bounds(recv, regs.size())) {
            return false;
        }
        thiz = regs[recv].o;
        // CheckJNI aborts on Call*MethodA(null, ...); match Dalvik and throw NPE.
        // Throw BEFORE PushLocalFrame so the exception local is not discarded by Pop.
        if (thiz == nullptr) {
            throw_npe(env, "VMP invoke on null");
            return false;
        }
        param_regs = arg_regs + 1;
        param_regc = static_cast<uint8_t>(argc - 1);
    }
    jvalue args_buf[32];
    std::vector<jvalue> args_vec;
    jvalue* args = args_buf;
    if (param_regc > 32) {
        args_vec.resize(param_regc);
        args = args_vec.data();
    }
    if (!fill_jargs(sig.c_str(), param_regs, param_regc, regs, args, nullptr)) {
        return false;
    }

    const char* ret = return_type_of_sig(sig.c_str());

    // Frame scopes Call* locals only; object results promoted via pop() to outer table.
    JniLocalFrame frame(env, 64);

    auto finish_object = [&](jobject v) -> bool {
        if (env->ExceptionCheck()) {
            return false;
        }
        pending.valid = true;
        // Take Call* ownership and promote out of the local frame.
        pending.o = frame.pop(v);
        pending.o_global = false;
        pending.k = RK_L;
        pending.i = 0;
        return true;
    };

    if (op == OP_INVOKE_STATIC) {
        switch (ret[0]) {
            case 'V':
                env->CallStaticVoidMethodA(cls, mid, args);
                return !env->ExceptionCheck();
            case 'Z': {
                jboolean v = env->CallStaticBooleanMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v ? 1 : 0;
                return true;
            }
            case 'B': {
                jbyte v = env->CallStaticByteMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'S': {
                jshort v = env->CallStaticShortMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'C': {
                jchar v = env->CallStaticCharMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'I': {
                jint v = env->CallStaticIntMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'F': {
                jfloat v = env->CallStaticFloatMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                memcpy(&pending.i, &v, sizeof(v));
                return true;
            }
            case 'J': {
                jlong v = env->CallStaticLongMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.j = v;
                return true;
            }
            case 'D': {
                jdouble v = env->CallStaticDoubleMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                memcpy(&pending.j, &v, sizeof(v));
                return true;
            }
            default: {
                jobject v = env->CallStaticObjectMethodA(cls, mid, args);
                return finish_object(v);
            }
        }
    }

    if (op == OP_INVOKE_SUPER || op == OP_INVOKE_DIRECT) {
        switch (ret[0]) {
            case 'V':
                env->CallNonvirtualVoidMethodA(thiz, cls, mid, args);
                return !env->ExceptionCheck();
            case 'Z': {
                jboolean v = env->CallNonvirtualBooleanMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v ? 1 : 0;
                return true;
            }
            case 'B': {
                jbyte v = env->CallNonvirtualByteMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'S': {
                jshort v = env->CallNonvirtualShortMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'C': {
                jchar v = env->CallNonvirtualCharMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'I': {
                jint v = env->CallNonvirtualIntMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'F': {
                jfloat v = env->CallNonvirtualFloatMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                memcpy(&pending.i, &v, sizeof(v));
                return true;
            }
            case 'J': {
                jlong v = env->CallNonvirtualLongMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.j = v;
                return true;
            }
            case 'D': {
                jdouble v = env->CallNonvirtualDoubleMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                memcpy(&pending.j, &v, sizeof(v));
                return true;
            }
            default: {
                jobject v = env->CallNonvirtualObjectMethodA(thiz, cls, mid, args);
                return finish_object(v);
            }
        }
    }

    switch (ret[0]) {
        case 'V':
            env->CallVoidMethodA(thiz, mid, args);
            return !env->ExceptionCheck();
        case 'Z': {
            jboolean v = env->CallBooleanMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.i = v ? 1 : 0;
            return true;
        }
        case 'B': {
            jbyte v = env->CallByteMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.i = v;
            return true;
        }
        case 'S': {
            jshort v = env->CallShortMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.i = v;
            return true;
        }
        case 'C': {
            jchar v = env->CallCharMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.i = v;
            return true;
        }
        case 'I': {
            jint v = env->CallIntMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.i = v;
            return true;
        }
        case 'F': {
            jfloat v = env->CallFloatMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            memcpy(&pending.i, &v, sizeof(v));
            return true;
        }
        case 'J': {
            jlong v = env->CallLongMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.j = v;
            return true;
        }
        case 'D': {
            jdouble v = env->CallDoubleMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            memcpy(&pending.j, &v, sizeof(v));
            return true;
        }
        default: {
            jobject v = env->CallObjectMethodA(thiz, mid, args);
            return finish_object(v);
        }
    }
}

static bool get_static_field(JNIEnv* env, const std::string& desc, uint8_t kind, Reg* dst) {
    std::string owner;
    std::string name;
    std::string type;
    if (!parse_member_ref(desc, &owner, &name, &type)) {
        return false;
    }
    if (!type.empty() && type[0] == ':') {
        type = type.substr(1);
    }
    jclass cls = find_class_desc(env, owner);
    if (cls == nullptr) {
        return false;
    }
    jfieldID fid = env->GetStaticFieldID(cls, name.c_str(), type.c_str());
    if (fid == nullptr) {
        return false;
    }
    switch (kind) {
        case KIND_I:
            reg_as_i(env, dst);
            if (type == "F") {
                jfloat f = env->GetStaticFloatField(cls, fid);
                if (env->ExceptionCheck()) return false;
                memcpy(&dst->i, &f, sizeof(f));
                return true;
            }
            dst->i = env->GetStaticIntField(cls, fid);
            return !env->ExceptionCheck();
        case KIND_J:
            reg_as_j(env, dst);
            if (type == "D") {
                jdouble d = env->GetStaticDoubleField(cls, fid);
                if (env->ExceptionCheck()) return false;
                memcpy(&dst->j, &d, sizeof(d));
                return true;
            }
            dst->j = env->GetStaticLongField(cls, fid);
            return !env->ExceptionCheck();
        case KIND_Z:
            reg_as_i(env, dst);
            dst->i = env->GetStaticBooleanField(cls, fid) ? 1 : 0;
            return !env->ExceptionCheck();
        case KIND_B:
            reg_as_i(env, dst);
            dst->i = env->GetStaticByteField(cls, fid);
            return !env->ExceptionCheck();
        case KIND_S:
            reg_as_i(env, dst);
            dst->i = env->GetStaticShortField(cls, fid);
            return !env->ExceptionCheck();
        case KIND_C:
            reg_as_i(env, dst);
            dst->i = env->GetStaticCharField(cls, fid);
            return !env->ExceptionCheck();
        case KIND_L: {
            // reg_take_o skips Delete when old==got (sget into a reg that already holds
            // the same cookie) and clears ownership atomically — avoids stale Local.
            jobject got = env->GetStaticObjectField(cls, fid);
            if (env->ExceptionCheck()) {
                return false;
            }
            reg_take_o(env, dst, got);
            return true;
        }
        default:
            return false;
    }
}

static bool put_static_field(JNIEnv* env, const std::string& desc, uint8_t kind, const Reg& src) {
    std::string owner;
    std::string name;
    std::string type;
    if (!parse_member_ref(desc, &owner, &name, &type)) {
        return false;
    }
    if (!type.empty() && type[0] == ':') {
        type = type.substr(1);
    }
    jclass cls = find_class_desc(env, owner);
    if (cls == nullptr) {
        return false;
    }
    jfieldID fid = env->GetStaticFieldID(cls, name.c_str(), type.c_str());
    if (fid == nullptr) {
        return false;
    }
    switch (kind) {
        case KIND_I:
            if (type == "F") {
                jfloat f;
                memcpy(&f, &src.i, sizeof(f));
                env->SetStaticFloatField(cls, fid, f);
            } else {
                env->SetStaticIntField(cls, fid, src.i);
            }
            return !env->ExceptionCheck();
        case KIND_J:
            if (type == "D") {
                jdouble d;
                memcpy(&d, &src.j, sizeof(d));
                env->SetStaticDoubleField(cls, fid, d);
            } else {
                env->SetStaticLongField(cls, fid, src.j);
            }
            return !env->ExceptionCheck();
        case KIND_Z:
            env->SetStaticBooleanField(cls, fid, src.i != 0 ? JNI_TRUE : JNI_FALSE);
            return !env->ExceptionCheck();
        case KIND_B:
            env->SetStaticByteField(cls, fid, static_cast<jbyte>(src.i));
            return !env->ExceptionCheck();
        case KIND_S:
            env->SetStaticShortField(cls, fid, static_cast<jshort>(src.i));
            return !env->ExceptionCheck();
        case KIND_C:
            env->SetStaticCharField(cls, fid, static_cast<jchar>(src.i));
            return !env->ExceptionCheck();
        case KIND_L:
            env->SetStaticObjectField(cls, fid, src.o);
            return !env->ExceptionCheck();
        default:
            return false;
    }
}

static bool get_instance_field(JNIEnv* env, const std::string& desc, uint8_t kind,
                               jobject obj, Reg* dst) {
    if (obj == nullptr) {
        throw_npe(env, "iget on null");
        return false;
    }
    std::string owner;
    std::string name;
    std::string type;
    if (!parse_member_ref(desc, &owner, &name, &type)) {
        return false;
    }
    if (!type.empty() && type[0] == ':') {
        type = type.substr(1);
    }
    jclass cls = find_class_desc(env, owner);
    if (cls == nullptr) {
        return false;
    }
    jfieldID fid = env->GetFieldID(cls, name.c_str(), type.c_str());
    if (fid == nullptr) {
        return false;
    }
    // IMPORTANT: do NOT reg_as_i/j(dst) before Get*Field — dst may alias the
    // object register (iget v0, v0, Field). Dropping dst first deletes the live
    // object local → GetIntField SIGSEGV (fault 0xb1). Seen on Alipay m.u.n.f.
    switch (kind) {
        case KIND_I: {
            if (type == "F") {
                jfloat f = env->GetFloatField(obj, fid);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                memcpy(&dst->i, &f, sizeof(f));
                return true;
            }
            jint v = env->GetIntField(obj, fid);
            if (env->ExceptionCheck()) return false;
            reg_as_i(env, dst);
            dst->i = v;
            return true;
        }
        case KIND_J: {
            if (type == "D") {
                jdouble d = env->GetDoubleField(obj, fid);
                if (env->ExceptionCheck()) return false;
                reg_as_j(env, dst);
                memcpy(&dst->j, &d, sizeof(d));
                return true;
            }
            jlong v = env->GetLongField(obj, fid);
            if (env->ExceptionCheck()) return false;
            reg_as_j(env, dst);
            dst->j = v;
            return true;
        }
        case KIND_Z: {
            jboolean v = env->GetBooleanField(obj, fid);
            if (env->ExceptionCheck()) return false;
            reg_as_i(env, dst);
            dst->i = v ? 1 : 0;
            return true;
        }
        case KIND_B: {
            jbyte v = env->GetByteField(obj, fid);
            if (env->ExceptionCheck()) return false;
            reg_as_i(env, dst);
            dst->i = v;
            return true;
        }
        case KIND_S: {
            jshort v = env->GetShortField(obj, fid);
            if (env->ExceptionCheck()) return false;
            reg_as_i(env, dst);
            dst->i = v;
            return true;
        }
        case KIND_C: {
            jchar v = env->GetCharField(obj, fid);
            if (env->ExceptionCheck()) return false;
            reg_as_i(env, dst);
            dst->i = v;
            return true;
        }
        case KIND_L: {
            // Get first — dst may alias obj (iget-object vX, vX, field).
            // reg_take_o skips Delete when old==got (same cookie / OEM NewLocalRef).
            jobject got = env->GetObjectField(obj, fid);
            if (env->ExceptionCheck()) {
                return false;
            }
            reg_take_o(env, dst, got);
            return true;
        }
        default:
            return false;
    }
}

static bool put_instance_field(JNIEnv* env, const std::string& desc, uint8_t kind,
                               jobject obj, const Reg& src) {
    if (obj == nullptr) {
        throw_npe(env, "iput on null");
        return false;
    }
    std::string owner;
    std::string name;
    std::string type;
    if (!parse_member_ref(desc, &owner, &name, &type)) {
        return false;
    }
    if (!type.empty() && type[0] == ':') {
        type = type.substr(1);
    }
    jclass cls = find_class_desc(env, owner);
    if (cls == nullptr) {
        return false;
    }
    jfieldID fid = env->GetFieldID(cls, name.c_str(), type.c_str());
    if (fid == nullptr) {
        return false;
    }
    switch (kind) {
        case KIND_I:
            if (type == "F") {
                jfloat f;
                memcpy(&f, &src.i, sizeof(f));
                env->SetFloatField(obj, fid, f);
            } else {
                env->SetIntField(obj, fid, src.i);
            }
            return !env->ExceptionCheck();
        case KIND_J:
            if (type == "D") {
                jdouble d;
                memcpy(&d, &src.j, sizeof(d));
                env->SetDoubleField(obj, fid, d);
            } else {
                env->SetLongField(obj, fid, src.j);
            }
            return !env->ExceptionCheck();
        case KIND_Z:
            env->SetBooleanField(obj, fid, src.i != 0 ? JNI_TRUE : JNI_FALSE);
            return !env->ExceptionCheck();
        case KIND_B:
            env->SetByteField(obj, fid, static_cast<jbyte>(src.i));
            return !env->ExceptionCheck();
        case KIND_S:
            env->SetShortField(obj, fid, static_cast<jshort>(src.i));
            return !env->ExceptionCheck();
        case KIND_C:
            env->SetCharField(obj, fid, static_cast<jchar>(src.i));
            return !env->ExceptionCheck();
        case KIND_L:
            env->SetObjectField(obj, fid, src.o);
            return !env->ExceptionCheck();
        default:
            return false;
    }
}

static jobject new_array_for_type(JNIEnv* env, const std::string& type, jsize len) {
    if (type == "[Z") return env->NewBooleanArray(len);
    if (type == "[B") return env->NewByteArray(len);
    if (type == "[S") return env->NewShortArray(len);
    if (type == "[C") return env->NewCharArray(len);
    if (type == "[I") return env->NewIntArray(len);
    if (type == "[J") return env->NewLongArray(len);
    if (type == "[F") return env->NewFloatArray(len);
    if (type == "[D") return env->NewDoubleArray(len);
    jclass elem = find_class_desc(env, type.substr(1));
    if (elem == nullptr) return nullptr;
    return env->NewObjectArray(len, elem, nullptr);
}

static uint8_t kind_of_array_type(const std::string& type) {
    if (type == "[I" || type == "[F") return KIND_I;
    if (type == "[J" || type == "[D") return KIND_J;
    if (type == "[Z") return KIND_Z;
    if (type == "[B") return KIND_B;
    if (type == "[S") return KIND_S;
    if (type == "[C") return KIND_C;
    return KIND_L;
}

static bool aget(JNIEnv* env, jarray arr, int32_t idx, uint8_t kind, Reg* dst) {
    if (arr == nullptr) {
        throw_npe(env, "aget on null");
        return false;
    }
    auto& c = jni_cache();
    // IMPORTANT: do NOT reg_as_i/j(dst) before reading arr — dst may alias the
    // array register (aget v0, v0, v1). Dropping dst first deletes the live array
    // local → IsInstanceOf/Get*ArrayRegion SIGSEGV (fault 0x31). Seen on Alipay
    // m.u.j → m.n.a under nested True-VMP.
    switch (kind) {
        case KIND_I: {
            jfloat fv;
            jint iv;
            jclass floatArrCls = c.float_arr != nullptr ? c.float_arr : find_jni_class(env, "[F");
            if (floatArrCls != nullptr && env->IsInstanceOf(arr, floatArrCls)) {
                env->GetFloatArrayRegion(static_cast<jfloatArray>(arr), idx, 1, &fv);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                memcpy(&dst->i, &fv, sizeof(fv));
                return true;
            }
            jclass intArrCls = find_jni_class(env, "[I");
            if (intArrCls == nullptr || !env->IsInstanceOf(arr, intArrCls)) {
                throw_cce(env, "aget int/float bad array");
                return false;
            }
            env->GetIntArrayRegion(static_cast<jintArray>(arr), idx, 1, &iv);
            if (env->ExceptionCheck()) return false;
            reg_as_i(env, dst);
            dst->i = iv;
            return true;
        }
        case KIND_J: {
            jdouble dv;
            jlong lv;
            jclass doubleArrCls = c.double_arr != nullptr ? c.double_arr : find_jni_class(env, "[D");
            if (doubleArrCls != nullptr && env->IsInstanceOf(arr, doubleArrCls)) {
                env->GetDoubleArrayRegion(static_cast<jdoubleArray>(arr), idx, 1, &dv);
                if (env->ExceptionCheck()) return false;
                reg_as_j(env, dst);
                memcpy(&dst->j, &dv, sizeof(dv));
                return true;
            }
            jclass longArrCls = find_jni_class(env, "[J");
            if (longArrCls == nullptr || !env->IsInstanceOf(arr, longArrCls)) {
                throw_cce(env, "aget long/double bad array");
                return false;
            }
            env->GetLongArrayRegion(static_cast<jlongArray>(arr), idx, 1, &lv);
            if (env->ExceptionCheck()) return false;
            reg_as_j(env, dst);
            dst->j = lv;
            return true;
        }
        case KIND_Z: {
            jboolean zv;
            jbyte bv;
            jclass boolArrCls = c.bool_arr != nullptr ? c.bool_arr : find_jni_class(env, "[Z");
            if (boolArrCls != nullptr && env->IsInstanceOf(arr, boolArrCls)) {
                env->GetBooleanArrayRegion(static_cast<jbooleanArray>(arr), idx, 1, &zv);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                dst->i = zv ? 1 : 0;
                return true;
            }
            jclass byteArrCls = find_jni_class(env, "[B");
            if (byteArrCls != nullptr && env->IsInstanceOf(arr, byteArrCls)) {
                env->GetByteArrayRegion(static_cast<jbyteArray>(arr), idx, 1, &bv);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                dst->i = bv;
                return true;
            }
            throw_cce(env, "aget-boolean bad array");
            return false;
        }
        case KIND_B: {
            jboolean zv;
            jbyte bv;
            jclass boolArrCls = c.bool_arr != nullptr ? c.bool_arr : find_jni_class(env, "[Z");
            if (boolArrCls != nullptr && env->IsInstanceOf(arr, boolArrCls)) {
                env->GetBooleanArrayRegion(static_cast<jbooleanArray>(arr), idx, 1, &zv);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                dst->i = zv ? 1 : 0;
                return true;
            }
            jclass byteArrCls = find_jni_class(env, "[B");
            if (byteArrCls != nullptr && env->IsInstanceOf(arr, byteArrCls)) {
                env->GetByteArrayRegion(static_cast<jbyteArray>(arr), idx, 1, &bv);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                dst->i = bv;
                return true;
            }
            throw_cce(env, "aget-byte bad array");
            return false;
        }
        case KIND_S: {
            jchar cv;
            jshort sv;
            jclass charArrCls = c.char_arr != nullptr ? c.char_arr : find_jni_class(env, "[C");
            if (charArrCls != nullptr && env->IsInstanceOf(arr, charArrCls)) {
                env->GetCharArrayRegion(static_cast<jcharArray>(arr), idx, 1, &cv);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                dst->i = cv;
                return true;
            }
            jclass shortArrCls = find_jni_class(env, "[S");
            if (shortArrCls != nullptr && env->IsInstanceOf(arr, shortArrCls)) {
                env->GetShortArrayRegion(static_cast<jshortArray>(arr), idx, 1, &sv);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                dst->i = sv;
                return true;
            }
            throw_cce(env, "aget-short bad array");
            return false;
        }
        case KIND_C: {
            jchar cv;
            jshort sv;
            jbyte bv;
            jclass charArrCls = c.char_arr != nullptr ? c.char_arr : find_jni_class(env, "[C");
            if (charArrCls != nullptr && env->IsInstanceOf(arr, charArrCls)) {
                env->GetCharArrayRegion(static_cast<jcharArray>(arr), idx, 1, &cv);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                dst->i = cv;
                return true;
            }
            jclass shortArrCls = find_jni_class(env, "[S");
            if (shortArrCls != nullptr && env->IsInstanceOf(arr, shortArrCls)) {
                env->GetShortArrayRegion(static_cast<jshortArray>(arr), idx, 1, &sv);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                dst->i = static_cast<uint16_t>(sv);
                return true;
            }
            jclass byteArrCls = find_jni_class(env, "[B");
            if (byteArrCls != nullptr && env->IsInstanceOf(arr, byteArrCls)) {
                env->GetByteArrayRegion(static_cast<jbyteArray>(arr), idx, 1, &bv);
                if (env->ExceptionCheck()) return false;
                reg_as_i(env, dst);
                dst->i = static_cast<uint8_t>(bv);
                return true;
            }
            throw_cce(env, "aget-char bad array");
            return false;
        }
        case KIND_L: {
            jobjectArray a = static_cast<jobjectArray>(arr);
            // Get first — dst may alias the array register.
            jobject got = env->GetObjectArrayElement(a, idx);
            if (env->ExceptionCheck()) {
                return false;
            }
            reg_take_o(env, dst, got);
            return true;
        }
        default:
            return false;
    }
}

static bool aput(JNIEnv* env, jarray arr, int32_t idx, uint8_t kind, const Reg& src) {
    if (arr == nullptr) {
        throw_npe(env, "aput on null");
        return false;
    }
    auto& c = jni_cache();
    switch (kind) {
        case KIND_I: {
            jclass floatArrCls = c.float_arr != nullptr ? c.float_arr : find_jni_class(env, "[F");
            if (floatArrCls != nullptr && env->IsInstanceOf(arr, floatArrCls)) {
                jfloat v;
                memcpy(&v, &src.i, sizeof(v));
                env->SetFloatArrayRegion(static_cast<jfloatArray>(arr), idx, 1, &v);
            } else {
                jint v = src.i;
                env->SetIntArrayRegion(static_cast<jintArray>(arr), idx, 1, &v);
            }
            return !env->ExceptionCheck();
        }
        case KIND_J: {
            jclass doubleArrCls = c.double_arr != nullptr ? c.double_arr : find_jni_class(env, "[D");
            if (doubleArrCls != nullptr && env->IsInstanceOf(arr, doubleArrCls)) {
                jdouble v;
                memcpy(&v, &src.j, sizeof(v));
                env->SetDoubleArrayRegion(static_cast<jdoubleArray>(arr), idx, 1, &v);
            } else {
                jlong v = src.j;
                env->SetLongArrayRegion(static_cast<jlongArray>(arr), idx, 1, &v);
            }
            return !env->ExceptionCheck();
        }
        case KIND_Z: {
            jboolean v = src.i != 0 ? JNI_TRUE : JNI_FALSE;
            env->SetBooleanArrayRegion(static_cast<jbooleanArray>(arr), idx, 1, &v);
            return !env->ExceptionCheck();
        }
        case KIND_B: {
            jclass boolArrCls = c.bool_arr != nullptr ? c.bool_arr : find_jni_class(env, "[Z");
            if (boolArrCls != nullptr && env->IsInstanceOf(arr, boolArrCls)) {
                jboolean v = src.i != 0 ? JNI_TRUE : JNI_FALSE;
                env->SetBooleanArrayRegion(static_cast<jbooleanArray>(arr), idx, 1, &v);
            } else {
                jbyte v = static_cast<jbyte>(src.i);
                env->SetByteArrayRegion(static_cast<jbyteArray>(arr), idx, 1, &v);
            }
            return !env->ExceptionCheck();
        }
        case KIND_S: {
            jclass charArrCls = c.char_arr != nullptr ? c.char_arr : find_jni_class(env, "[C");
            if (charArrCls != nullptr && env->IsInstanceOf(arr, charArrCls)) {
                jchar v = static_cast<jchar>(src.i);
                env->SetCharArrayRegion(static_cast<jcharArray>(arr), idx, 1, &v);
            } else {
                jshort v = static_cast<jshort>(src.i);
                env->SetShortArrayRegion(static_cast<jshortArray>(arr), idx, 1, &v);
            }
            return !env->ExceptionCheck();
        }
        case KIND_C: {
            // Type-check like KIND_S path — avoid SIGSEGV on non-[C].
            jclass charArrCls = c.char_arr != nullptr ? c.char_arr : find_jni_class(env, "[C");
            if (charArrCls != nullptr && env->IsInstanceOf(arr, charArrCls)) {
                jchar v = static_cast<jchar>(src.i);
                env->SetCharArrayRegion(static_cast<jcharArray>(arr), idx, 1, &v);
            } else {
                jclass shortArrCls = find_jni_class(env, "[S");
                if (shortArrCls != nullptr && env->IsInstanceOf(arr, shortArrCls)) {
                    jshort v = static_cast<jshort>(src.i);
                    env->SetShortArrayRegion(static_cast<jshortArray>(arr), idx, 1, &v);
                } else {
                    throw_cce(env, "aput-char bad array");
                    return false;
                }
            }
            return !env->ExceptionCheck();
        }
        case KIND_L:
            env->SetObjectArrayElement(static_cast<jobjectArray>(arr), idx, src.o);
            return !env->ExceptionCheck();
        default:
            return false;
    }
}

static bool filled_new_array(JNIEnv* env, const std::string& type,
                             const uint8_t* arg_regs, uint8_t argc,
                             const std::vector<Reg>& regs, PendingResult& pending) {
    clear_pending(env, pending);
    jobject arr = new_array_for_type(env, type, argc);
    if (arr == nullptr || env->ExceptionCheck()) {
        return false;
    }
    uint8_t kind = kind_of_array_type(type);
    for (uint8_t i = 0; i < argc; i++) {
        uint8_t r = arg_regs[i];
        if (!reg_bounds(r, regs.size())) {
            env->DeleteLocalRef(arr);
            return false;
        }
        if (kind == KIND_J && !reg_bounds_wide(r, regs.size())) {
            env->DeleteLocalRef(arr);
            return false;
        }
        if (!aput(env, static_cast<jarray>(arr), i, kind, regs[r])) {
            env->DeleteLocalRef(arr);
            return false;
        }
    }
    pending.valid = true;
    pending.o = arr;
    pending.o_global = false;
    pending.k = RK_L;
    pending.i = 0;
    return true;
}

static bool dispatch_exception(JNIEnv* env, const Pvm2Image& img, size_t fault_pc,
                               size_t* pc, jobject* stashed_exception) {
    jthrowable ex = env->ExceptionOccurred();
    if (ex == nullptr) {
        return false;
    }
    // Clear FIRST — JNI forbids NewLocalRef/NewGlobalRef with a pending exception.
    // The ExceptionOccurred local remains valid after Clear until we DeleteLocalRef it.
    env->ExceptionClear();

    bool held_global = false;
    jobject held = dup_owned_ref(env, ex, &held_global);
    if (held_global || held != static_cast<jobject>(ex)) {
        env->DeleteLocalRef(ex);
    }
    if (held == nullptr) {
        return false;
    }

    for (const auto& h : img.handlers) {
        if (fault_pc < h.start || fault_pc >= h.end) {
            continue;
        }
        bool match = false;
        if (h.catch_type_idx == PVM2_CATCH_ALL) {
            match = true;
        } else if (h.catch_type_idx < img.types.size()) {
            jclass catch_cls = find_class_desc(env, img.types[h.catch_type_idx]);
            if (catch_cls != nullptr) {
                match = env->IsInstanceOf(held, catch_cls) == JNI_TRUE;
            }
        }
        if (!match) {
            continue;
        }
        release_stash(env, stashed_exception);
        if (held_global) {
            jobject local = global_to_local(env, held);
            if (local == nullptr) {
                // Rare OOM: rethrow via Global so the throwable is not dropped.
                env->Throw(static_cast<jthrowable>(held));
                release_ref(env, held, true);
                return false;
            }
            held = local;
            held_global = false;
        }
        // Transfer ownership into stash — no NewLocalRef+Delete alias.
        *stashed_exception = held;
        *pc = h.handler_pc;
        return true;
    }

    if (held_global) {
        jobject local = global_to_local(env, held);
        if (local == nullptr) {
            env->Throw(static_cast<jthrowable>(held));
            release_ref(env, held, true);
            return false;
        }
        held = local;
        held_global = false;
    }
    if (held != nullptr) {
        env->Throw(static_cast<jthrowable>(held));
        // Pending exception keeps the object alive; drop our owned local.
        release_ref(env, held, false);
    }
    return false;
}

struct VmpLru {
    std::mutex mu;
    std::list<CodeItem*> order; // front = MRU
    std::unordered_map<CodeItem*, std::list<CodeItem*>::iterator> pos;
};

static VmpLru g_vmp_lru;

static int vmp_lru_cap() {
    int n = runtime_state().config.vmp_lru;
    if (n < 1) n = 1;
    if (n > 256) n = 256;
    return n;
}

static void wipe_vmp_plaintext(CodeItem* item) {
    if (item == nullptr) return;
    if (!item->vm_image.empty()) {
        memset(item->vm_image.data(), 0, item->vm_image.size());
        item->vm_image.clear();
        item->vm_image.shrink_to_fit();
    }
    item->parsed_vm.reset();
}

static void lru_remove_item(CodeItem* item) {
    if (item == nullptr) return;
    std::lock_guard<std::mutex> lock(g_vmp_lru.mu);
    auto it = g_vmp_lru.pos.find(item);
    if (it == g_vmp_lru.pos.end()) return;
    g_vmp_lru.order.erase(it->second);
    g_vmp_lru.pos.erase(it);
}

static void lru_touch(CodeItem* item) {
    if (item == nullptr) return;
    std::vector<CodeItem*> victims;
    {
        std::lock_guard<std::mutex> lock(g_vmp_lru.mu);
        auto it = g_vmp_lru.pos.find(item);
        if (it != g_vmp_lru.pos.end()) {
            g_vmp_lru.order.erase(it->second);
        }
        g_vmp_lru.order.push_front(item);
        g_vmp_lru.pos[item] = g_vmp_lru.order.begin();

        const int cap = vmp_lru_cap();
        while (static_cast<int>(g_vmp_lru.order.size()) > cap) {
            CodeItem* victim = nullptr;
            for (auto rit = g_vmp_lru.order.rbegin(); rit != g_vmp_lru.order.rend(); ++rit) {
                CodeItem* cand = *rit;
                if (cand == nullptr || cand == item) continue;
                if (cand->vmp_in_use.load(std::memory_order_acquire) > 0) continue;
                victim = cand;
                break;
            }
            if (victim == nullptr) break;
            auto pos_it = g_vmp_lru.pos.find(victim);
            if (pos_it != g_vmp_lru.pos.end()) {
                g_vmp_lru.order.erase(pos_it->second);
                g_vmp_lru.pos.erase(pos_it);
            }
            victims.push_back(victim);
        }
    }
    for (CodeItem* v : victims) {
        std::lock_guard<std::mutex> plock(v->parse_mu);
        if (v->vmp_in_use.load(std::memory_order_acquire) > 0) {
            continue;
        }
        wipe_vmp_plaintext(v);
    }
}

struct VmpUsePin {
    CodeItem* item = nullptr;
    void acquire(CodeItem* i) {
        item = i;
        item->vmp_in_use.fetch_add(1, std::memory_order_acq_rel);
    }
    ~VmpUsePin() {
        if (item == nullptr) return;
        item->vmp_in_use.fetch_sub(1, std::memory_order_acq_rel);
        if (!runtime_state().environment_degraded.load(std::memory_order_acquire)) {
            return;
        }
        {
            std::lock_guard<std::mutex> plock(item->parse_mu);
            if (item->vmp_in_use.load(std::memory_order_acquire) != 0) {
                return;
            }
            wipe_vmp_plaintext(item);
        }
        lru_remove_item(item);
    }
    VmpUsePin() = default;
    VmpUsePin(const VmpUsePin&) = delete;
    VmpUsePin& operator=(const VmpUsePin&) = delete;
};

/** Caller holds item->parse_mu. Ciphertext at item->insns is left intact. */
static bool ensure_true_vmp_plaintext_locked(CodeItem* item) {
    auto& state = runtime_state();
    if (item->vm_image.empty()) {
        if (state.config.insns_aes_key.size() != 16) {
            return false;
        }
        if (item->insns == nullptr || item->insns_size == 0 || item->plain_insns_size == 0) {
            return false;
        }
        item->vm_image.resize(item->plain_insns_size);
        if (!crypto::aes128_gcm_decrypt(state.config.insns_aes_key.data(),
                                        item->insns, item->insns_size,
                                        item->vm_image.data(), item->vm_image.size())) {
            item->vm_image.clear();
            item->vm_image.shrink_to_fit();
            return false;
        }
    }
    if (item->parsed_vm == nullptr || !item->parsed_vm->valid) {
        auto parsed = std::make_unique<Pvm2Image>();
        if (!parse_pvm2(item->vm_image.data(), item->vm_image.size(), parsed.get())
                || !parsed->valid) {
            return false;
        }
        item->parsed_vm = std::move(parsed);
    }
    return true;
}

void clear_true_vmp_lru() {
    std::vector<CodeItem*> wipe_list;
    std::vector<CodeItem*> pinned;
    {
        std::lock_guard<std::mutex> lock(g_vmp_lru.mu);
        for (CodeItem* item : g_vmp_lru.order) {
            if (item == nullptr) continue;
            if (item->vmp_in_use.load(std::memory_order_acquire) > 0) {
                pinned.push_back(item);
            } else {
                wipe_list.push_back(item);
            }
        }
        g_vmp_lru.order.clear();
        g_vmp_lru.pos.clear();
        for (CodeItem* p : pinned) {
            g_vmp_lru.order.push_front(p);
            g_vmp_lru.pos[p] = g_vmp_lru.order.begin();
        }
    }
    for (CodeItem* v : wipe_list) {
        std::lock_guard<std::mutex> plock(v->parse_mu);
        if (v->vmp_in_use.load(std::memory_order_acquire) > 0) {
            continue;
        }
        wipe_vmp_plaintext(v);
    }
}

PROTECTOR_ENCRYPT bool prepare_true_vmp_images() {
    auto& state = runtime_state();
    if (state.config.insns_aes_key.size() != 16) {
        return false;
    }
    risk::so_guard_check();
    if (state.environment_degraded.load(std::memory_order_acquire)
            && state.config.rasp_action.load(std::memory_order_relaxed)
                    == static_cast<int>(RaspAction::Degrade)) {
        PLOGE("TRUE_VMP prepare refused: environment degraded");
        return false;
    }
    int count = 0;
    for (auto& dex : state.code_map) {
        for (auto& kv : dex.second) {
            CodeItem* item = kv.second;
            if (item == nullptr || (item->flags & FLAG_TRUE_VMP) == 0) {
                continue;
            }
            if (item->insns == nullptr || item->insns_size == 0 || item->plain_insns_size == 0) {
                PLOGE("TRUE_VMP missing payload method=%u", item->method_idx);
                return false;
            }
            count++;
        }
    }
    PLOGI("TRUE_VMP indexed count=%d lru=%d", count, vmp_lru_cap());
    return true;
}

PROTECTOR_ENCRYPT static jobject interpret_body(JNIEnv* env, int dex_index, uint32_t method_idx,
                                                 jobjectArray args) {
    if (!ensure_well_known_classes(env)) {
        throw_runtime(env, "VMP class cache");
        return nullptr;
    }
    auto& box = jni_cache();

    auto& state = runtime_state();
    auto dex_it = state.code_map.find(dex_index);
    if (dex_it == state.code_map.end()) {
        throw_runtime(env, "VMP bad dex");
        return nullptr;
    }
    auto m_it = dex_it->second.find(method_idx);
    if (m_it == dex_it->second.end() || m_it->second == nullptr) {
        throw_runtime(env, "VMP bad method");
        return nullptr;
    }
    CodeItem* item = m_it->second;
    if ((item->flags & FLAG_TRUE_VMP) == 0 || item->vm_image.empty()) {
        throw_runtime(env, "VMP not ready");
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(item->parse_mu);
        if (item->parsed_vm == nullptr || !item->parsed_vm->valid) {
            auto parsed = std::make_unique<Pvm2Image>();
            if (!parse_pvm2(item->vm_image.data(), item->vm_image.size(), parsed.get())
                    || !parsed->valid) {
                throw_runtime(env, "VMP bad image");
                return nullptr;
            }
            item->parsed_vm = std::move(parsed);
        }
    }
    const Pvm2Image& img = *item->parsed_vm;

    std::vector<Reg> regs(img.reg_count);
    // L3: reserve locals for registers + invoke scratch so the table does not recycle mid-run.
    (void)env->EnsureLocalCapacity(static_cast<jint>(img.reg_count) + 256);

    const int arg_count = args ? env->GetArrayLength(args) : 0;
    // v2–v4: last register is lit scratch. v5: scratch_extra (1–3) after the Dalvik frame.
    const int scratch_reserve = static_cast<int>(img.scratch_extra);
    if (static_cast<int>(img.reg_count) < static_cast<int>(img.ins_size) + scratch_reserve) {
        throw_runtime(env, "VMP bad frame");
        return nullptr;
    }
    int param_base = static_cast<int>(img.reg_count) - static_cast<int>(img.ins_size) - scratch_reserve;
    if (param_base < 0) {
        throw_runtime(env, "VMP bad frame");
        return nullptr;
    }

    jclass intCls = box.integer_cls;
    jclass longCls = box.long_cls;
    jclass boolCls = box.boolean_cls;
    jclass floatCls = box.float_cls;
    jclass doubleCls = box.double_cls;

    PendingResult pending;
    jobject stashed_exception = nullptr;
    InterpFrameScope frame_scope(regs, pending, &stashed_exception);

    int r = param_base;
    for (int i = 0; i < arg_count; i++) {
        if (r >= static_cast<int>(img.reg_count)) {
            clear_regs(env, regs);
            throw_runtime(env, "VMP args overflow");
            return nullptr;
        }
        jobject a = env->GetObjectArrayElement(args, i);
        if (a == nullptr) {
            reg_take_o(env, &regs[r], nullptr);
            r += 1;
            continue;
        }
        if (env->IsInstanceOf(a, intCls)) {
            unbox_arg(env, a, "I", &regs[r]);
            env->DeleteLocalRef(a);
            r += 1;
        } else if (env->IsInstanceOf(a, longCls)) {
            unbox_arg(env, a, "J", &regs[r]);
            env->DeleteLocalRef(a);
            r += 2;
        } else if (env->IsInstanceOf(a, boolCls)) {
            unbox_arg(env, a, "Z", &regs[r]);
            env->DeleteLocalRef(a);
            r += 1;
        } else if (env->IsInstanceOf(a, floatCls)) {
            unbox_arg(env, a, "F", &regs[r]);
            env->DeleteLocalRef(a);
            r += 1;
        } else if (env->IsInstanceOf(a, doubleCls)) {
            unbox_arg(env, a, "D", &regs[r]);
            env->DeleteLocalRef(a);
            r += 2;
        } else {
            bool g = false;
            jobject copy = dup_owned_ref(env, a, &g);
            if (g || copy != a) {
                env->DeleteLocalRef(a);
            }
            reg_take_o(env, &regs[r], copy, g);
            r += 1;
        }
        if (env->ExceptionCheck()) {
            clear_regs(env, regs);
            return nullptr;
        }
    }

    const uint8_t* code = img.code.data();
    size_t code_size = img.code.size();
    size_t pc = 0;
    size_t fault_pc = 0;
    jobject result = nullptr;
    bool result_is_global = false;
    bool finished = false;

    while (!finished && pc < code_size) {
        fault_pc = pc;
        uint8_t wire = code[pc++];
        uint8_t op = demorph_op(img, wire);
        switch (op) {
            case OP_NOP:
                break;
            case OP_CONST: {
                if (pc + 5 > code_size) goto fail;
                uint8_t dst = code[pc++];
                int32_t imm = read_i32(code + pc) ^ img.imm_key;
                pc += 4;
                if (!reg_bounds(dst, regs.size())) goto fail;
                reg_as_i(env, &regs[dst]);
                regs[dst].i = imm;
                break;
            }
            case OP_CONST_WIDE: {
                if (pc + 9 > code_size) goto fail;
                uint8_t dst = code[pc++];
                int64_t imm = read_i64(code + pc) ^ imm_key64(img.imm_key);
                pc += 8;
                if (!reg_bounds_wide(dst, regs.size())) goto fail;
                reg_as_j(env, &regs[dst]);
                regs[dst].j = imm;
                break;
            }
            case OP_CONST_STR: {
                if (pc + 3 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint16_t idx = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(dst, regs.size()) || idx >= img.strings.size()) goto fail;
                reg_take_o(env, &regs[dst], env->NewStringUTF(img.strings[idx].c_str()));
                break;
            }
            case OP_MOVE: {
                if (pc + 2 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(src, regs.size())) goto fail;
                reg_as_i(env, &regs[dst]);
                regs[dst].i = regs[src].i;
                break;
            }
            case OP_MOVE_WIDE: {
                if (pc + 2 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds_wide(dst, regs.size()) || !reg_bounds_wide(src, regs.size())) goto fail;
                reg_as_j(env, &regs[dst]);
                regs[dst].j = regs[src].j;
                break;
            }
            case OP_MOVE_OBJ: {
                if (pc + 2 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(src, regs.size())) goto fail;
                if (dst == src) {
                    break;  // move-object vX, vX is a no-op
                }
                bool g = false;
                jobject copy = regs[src].o ? dup_owned_ref(env, regs[src].o, &g) : nullptr;
                reg_take_o(env, &regs[dst], copy, g);
                break;
            }
            case OP_GOTO: {
                if (pc + 2 > code_size) goto fail;
                int16_t rel = read_i16(code + pc);
                pc += 2;
                pc = static_cast<size_t>(static_cast<ptrdiff_t>(pc) + rel);
                break;
            }
            case OP_IF_CMP: {
                if (pc + 5 > code_size) goto fail;
                uint8_t cond = code[pc++];
                uint8_t a = code[pc++];
                uint8_t b = code[pc++];
                int16_t rel = read_i16(code + pc);
                pc += 2;
                if (!reg_bounds(a, regs.size()) || !reg_bounds(b, regs.size())) goto fail;
                if (eval_if_cmp(env, cond, regs[a], regs[b])) {
                    pc = static_cast<size_t>(static_cast<ptrdiff_t>(pc) + rel);
                }
                break;
            }
            case OP_IF_Z: {
                if (pc + 4 > code_size) goto fail;
                uint8_t cond = code[pc++];
                uint8_t a = code[pc++];
                int16_t rel = read_i16(code + pc);
                pc += 2;
                if (!reg_bounds(a, regs.size())) goto fail;
                if (eval_if_z(cond, regs[a])) {
                    pc = static_cast<size_t>(static_cast<ptrdiff_t>(pc) + rel);
                }
                break;
            }
            case OP_RETURN_VOID:
                finished = true;
                result = nullptr;
                break;
            case OP_RETURN: {
                if (pc + 1 > code_size) goto fail;
                uint8_t src = code[pc++];
                if (!reg_bounds(src, regs.size())) goto fail;
                if (img.ret_kind == RET_Z) {
                    result = box_bool(env, regs[src].i != 0);
                } else if (img.ret_kind == RET_F) {
                    jfloat f;
                    memcpy(&f, &regs[src].i, sizeof(f));
                    result = box_float(env, f);
                } else {
                    result = box_int(env, regs[src].i);
                }
                finished = true;
                break;
            }
            case OP_RETURN_WIDE: {
                if (pc + 1 > code_size) goto fail;
                uint8_t src = code[pc++];
                if (!reg_bounds_wide(src, regs.size())) goto fail;
                if (img.ret_kind == RET_D) {
                    jdouble d;
                    memcpy(&d, &regs[src].j, sizeof(d));
                    result = box_double(env, d);
                } else {
                    result = box_long(env, regs[src].j);
                }
                finished = true;
                break;
            }
            case OP_RETURN_OBJ: {
                if (pc + 1 > code_size) goto fail;
                uint8_t src = code[pc++];
                if (!reg_bounds(src, regs.size())) goto fail;
                // Survive clear_regs: never share a Local cookie with a register.
                if (regs[src].o != nullptr) {
                    result = env->NewGlobalRef(regs[src].o);
                    result_is_global = true;
                } else {
                    result = nullptr;
                    result_is_global = false;
                }
                finished = true;
                break;
            }
            case OP_BINOP: {
                if (pc + 4 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t b = code[pc++];
                uint8_t c = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(b, regs.size()) ||
                    !reg_bounds(c, regs.size())) {
                    goto fail;
                }
                int32_t out = 0;
                if (!binop_i32(env, bin, regs[b].i, regs[c].i, &out)) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                regs[dst].i = out;
                regs[dst].k = RK_I;
                reg_drop_obj(env, &regs[dst]);
                break;
            }
            case OP_BINOP_2ADDR: {
                if (pc + 3 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(src, regs.size())) goto fail;
                int32_t out = 0;
                if (!binop_i32(env, bin, regs[dst].i, regs[src].i, &out)) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                regs[dst].i = out;
                regs[dst].k = RK_I;
                reg_drop_obj(env, &regs[dst]);
                break;
            }
            case OP_BINOP_WIDE: {
                if (pc + 4 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t b = code[pc++];
                uint8_t c = code[pc++];
                // Dalvik shl/shr/ushr-long take a 32-bit shift count (narrow reg).
                const bool shift = is_shift_binop(bin);
                if (!reg_bounds_wide(dst, regs.size()) || !reg_bounds_wide(b, regs.size())) {
                    goto fail;
                }
                if (shift ? !reg_bounds(c, regs.size()) : !reg_bounds_wide(c, regs.size())) {
                    goto fail;
                }
                int64_t out = 0;
                int64_t rhs = shift ? static_cast<int64_t>(regs[c].i) : regs[c].j;
                if (!binop_i64(env, bin, regs[b].j, rhs, &out)) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                regs[dst].j = out;
                regs[dst].k = RK_J;
                reg_drop_obj(env, &regs[dst]);
                break;
            }
            case OP_BINOP_2ADDR_WIDE: {
                if (pc + 3 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                const bool shift = is_shift_binop(bin);
                if (!reg_bounds_wide(dst, regs.size())) {
                    goto fail;
                }
                if (shift ? !reg_bounds(src, regs.size()) : !reg_bounds_wide(src, regs.size())) {
                    goto fail;
                }
                int64_t out = 0;
                int64_t rhs = shift ? static_cast<int64_t>(regs[src].i) : regs[src].j;
                if (!binop_i64(env, bin, regs[dst].j, rhs, &out)) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                regs[dst].j = out;
                regs[dst].k = RK_J;
                reg_drop_obj(env, &regs[dst]);
                break;
            }
            case OP_BINOP_FLOAT: {
                if (pc + 4 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t b = code[pc++];
                uint8_t c = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(b, regs.size()) ||
                    !reg_bounds(c, regs.size())) {
                    goto fail;
                }
                reg_as_i(env, &regs[dst]);
                regs[dst].i = float_bits(binop_f32(bin, as_float(regs[b].i), as_float(regs[c].i)));
                break;
            }
            case OP_BINOP_2ADDR_FLOAT: {
                if (pc + 3 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(src, regs.size())) goto fail;
                int32_t bits = float_bits(
                        binop_f32(bin, as_float(regs[dst].i), as_float(regs[src].i)));
                reg_as_i(env, &regs[dst]);
                regs[dst].i = bits;
                break;
            }
            case OP_BINOP_DOUBLE: {
                if (pc + 4 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t b = code[pc++];
                uint8_t c = code[pc++];
                if (!reg_bounds_wide(dst, regs.size()) || !reg_bounds_wide(b, regs.size()) ||
                    !reg_bounds_wide(c, regs.size())) {
                    goto fail;
                }
                reg_as_j(env, &regs[dst]);
                regs[dst].j = double_bits(
                        binop_f64(bin, as_double(regs[b].j), as_double(regs[c].j)));
                break;
            }
            case OP_BINOP_2ADDR_DOUBLE: {
                if (pc + 3 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds_wide(dst, regs.size()) || !reg_bounds_wide(src, regs.size())) {
                    goto fail;
                }
                int64_t bits = double_bits(
                        binop_f64(bin, as_double(regs[dst].j), as_double(regs[src].j)));
                reg_as_j(env, &regs[dst]);
                regs[dst].j = bits;
                break;
            }
            case OP_UNOP: {
                if (pc + 3 > code_size) goto fail;
                uint8_t kind = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                bool wide_src = (kind == UN_NEG_LONG || kind == UN_NOT_LONG
                        || kind == UN_LONG_TO_INT || kind == UN_LONG_TO_FLOAT
                        || kind == UN_LONG_TO_DOUBLE || kind == UN_NEG_DOUBLE
                        || kind == UN_DOUBLE_TO_INT || kind == UN_DOUBLE_TO_LONG
                        || kind == UN_DOUBLE_TO_FLOAT);
                bool wide_dst = (kind == UN_NEG_LONG || kind == UN_NOT_LONG
                        || kind == UN_INT_TO_LONG || kind == UN_INT_TO_DOUBLE
                        || kind == UN_LONG_TO_DOUBLE || kind == UN_FLOAT_TO_LONG
                        || kind == UN_FLOAT_TO_DOUBLE || kind == UN_NEG_DOUBLE
                        || kind == UN_DOUBLE_TO_LONG);
                if (wide_dst ? !reg_bounds_wide(dst, regs.size()) : !reg_bounds(dst, regs.size())) {
                    goto fail;
                }
                if (wide_src ? !reg_bounds_wide(src, regs.size()) : !reg_bounds(src, regs.size())) {
                    goto fail;
                }
                Reg src_copy = regs[src];
                if (wide_dst) {
                    reg_as_j(env, &regs[dst]);
                } else {
                    reg_as_i(env, &regs[dst]);
                }
                if (!apply_unop(kind, &regs[dst], src_copy)) goto fail;
                break;
            }
            case OP_CMP: {
                if (pc + 4 > code_size) goto fail;
                uint8_t kind = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t b = code[pc++];
                uint8_t c = code[pc++];
                if (!reg_bounds(dst, regs.size())) goto fail;
                switch (kind) {
                    case CMP_FLOAT_L:
                    case CMP_FLOAT_G:
                        if (!reg_bounds(b, regs.size()) || !reg_bounds(c, regs.size())) goto fail;
                        reg_as_i(env, &regs[dst]);
                        regs[dst].i = cmp_float(as_float(regs[b].i), as_float(regs[c].i),
                                                kind == CMP_FLOAT_G);
                        break;
                    case CMP_DOUBLE_L:
                    case CMP_DOUBLE_G:
                        if (!reg_bounds_wide(b, regs.size()) || !reg_bounds_wide(c, regs.size())) {
                            goto fail;
                        }
                        reg_as_i(env, &regs[dst]);
                        regs[dst].i = cmp_double(as_double(regs[b].j), as_double(regs[c].j),
                                                 kind == CMP_DOUBLE_G);
                        break;
                    case CMP_LONG:
                        if (!reg_bounds_wide(b, regs.size()) || !reg_bounds_wide(c, regs.size())) {
                            goto fail;
                        }
                        reg_as_i(env, &regs[dst]);
                        regs[dst].i = cmp_long(regs[b].j, regs[c].j);
                        break;
                    default:
                        goto fail;
                }
                break;
            }
            case OP_MONITOR_ENTER: {
                if (pc + 1 > code_size) goto fail;
                uint8_t obj = code[pc++];
                if (!reg_bounds(obj, regs.size()) || regs[obj].o == nullptr) {
                    throw_npe(env, "monitor-enter on null");
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                if (env->MonitorEnter(regs[obj].o) != 0) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                break;
            }
            case OP_MONITOR_EXIT: {
                if (pc + 1 > code_size) goto fail;
                uint8_t obj = code[pc++];
                if (!reg_bounds(obj, regs.size()) || regs[obj].o == nullptr) {
                    throw_npe(env, "monitor-exit on null");
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                if (env->MonitorExit(regs[obj].o) != 0) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                break;
            }
            case OP_INVOKE_STATIC:
            case OP_INVOKE_VIRTUAL:
            case OP_INVOKE_DIRECT:
            case OP_INVOKE_INTERFACE:
            case OP_INVOKE_SUPER: {
                if (pc + 3 > code_size) goto fail;
                uint16_t mid = read_u16(code + pc);
                pc += 2;
                uint8_t argc = code[pc++];
                if (pc + argc > code_size) goto fail;
                if (mid >= img.methods.size()) goto fail;
                const uint8_t* arg_regs = code + pc;
                pc += argc;
                if (!invoke_method(env, op, img.methods[mid], arg_regs, argc, regs, pending)) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_pending(env, pending);
                        clear_regs(env, regs);
                        release_stash(env, &stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_MOVE_RESULT: {
                if (pc + 1 > code_size) goto fail;
                uint8_t dst = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !pending.valid) goto fail;
                reg_as_i(env, &regs[dst]);
                regs[dst].i = pending.i;
                clear_pending(env, pending);
                break;
            }
            case OP_MOVE_RESULT_WIDE: {
                if (pc + 1 > code_size) goto fail;
                uint8_t dst = code[pc++];
                if (!reg_bounds_wide(dst, regs.size()) || !pending.valid) goto fail;
                reg_as_j(env, &regs[dst]);
                regs[dst].j = pending.j;
                clear_pending(env, pending);
                break;
            }
            case OP_MOVE_RESULT_OBJ: {
                if (pc + 1 > code_size) goto fail;
                uint8_t dst = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !pending.valid) goto fail;
                // Transfer ownership of pending local ref — do not NewLocalRef+leak.
                jobject got = pending.o;
                bool g = pending.o_global;
                pending.o = nullptr;
                pending.o_global = false;
                pending.valid = false;
                pending.k = RK_I;
                reg_take_o(env, &regs[dst], got, g);
                break;
            }
            case OP_SGET: {
                if (pc + 4 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint16_t fid = read_u16(code + pc);
                pc += 2;
                uint8_t kind = code[pc++];
                if (!reg_bounds(dst, regs.size()) || fid >= img.fields.size()) goto fail;
                if (!get_static_field(env, img.fields[fid], kind, &regs[dst])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        release_stash(env, &stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_SPUT: {
                if (pc + 4 > code_size) goto fail;
                uint8_t src = code[pc++];
                uint16_t fid = read_u16(code + pc);
                pc += 2;
                uint8_t kind = code[pc++];
                if (!reg_bounds(src, regs.size()) || fid >= img.fields.size()) goto fail;
                if (!put_static_field(env, img.fields[fid], kind, regs[src])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        release_stash(env, &stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_IGET: {
                if (pc + 5 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t obj = code[pc++];
                uint16_t fid = read_u16(code + pc);
                pc += 2;
                uint8_t kind = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(obj, regs.size()) ||
                    fid >= img.fields.size()) {
                    goto fail;
                }
                if (!get_instance_field(env, img.fields[fid], kind, regs[obj].o, &regs[dst])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        release_stash(env, &stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_IPUT: {
                if (pc + 5 > code_size) goto fail;
                uint8_t src = code[pc++];
                uint8_t obj = code[pc++];
                uint16_t fid = read_u16(code + pc);
                pc += 2;
                uint8_t kind = code[pc++];
                if (!reg_bounds(src, regs.size()) || !reg_bounds(obj, regs.size()) ||
                    fid >= img.fields.size()) {
                    goto fail;
                }
                if (!put_instance_field(env, img.fields[fid], kind, regs[obj].o, regs[src])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        release_stash(env, &stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_NEW_INSTANCE: {
                if (pc + 3 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(dst, regs.size()) || tid >= img.types.size()) goto fail;
                jclass cls = find_class_desc(env, img.types[tid]);
                if (cls == nullptr) goto fail;
                reg_take_o(env, &regs[dst], env->AllocObject(cls));
                if (env->ExceptionCheck()) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                break;
            }
            case OP_NEW_ARRAY: {
                if (pc + 4 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t size_reg = code[pc++];
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(size_reg, regs.size()) ||
                    tid >= img.types.size()) {
                    goto fail;
                }
                jsize len = regs[size_reg].i;
                reg_take_o(env, &regs[dst], new_array_for_type(env, img.types[tid], len));
                if (env->ExceptionCheck()) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                break;
            }
            case OP_FILLED_NEW_ARRAY: {
                if (pc + 3 > code_size) goto fail;
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                uint8_t argc = code[pc++];
                if (pc + argc > code_size) goto fail;
                if (tid >= img.types.size()) goto fail;
                const uint8_t* arg_regs = code + pc;
                pc += argc;
                if (!filled_new_array(env, img.types[tid], arg_regs, argc, regs, pending)) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_pending(env, pending);
                        clear_regs(env, regs);
                        release_stash(env, &stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_ARRAY_LENGTH: {
                if (pc + 2 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t arr = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(arr, regs.size())) goto fail;
                if (regs[arr].o == nullptr) {
                    throw_npe(env, "array-length on null");
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                int32_t len = env->GetArrayLength(static_cast<jarray>(regs[arr].o));
                if (env->ExceptionCheck()) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_regs(env, regs);
                    release_stash(env, &stashed_exception);
                    return nullptr;
                }
                reg_as_i(env, &regs[dst]);
                regs[dst].i = len;
                break;
            }
            case OP_AGET: {
                if (pc + 4 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t arr = code[pc++];
                uint8_t idx = code[pc++];
                uint8_t kind = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(arr, regs.size()) ||
                    !reg_bounds(idx, regs.size())) {
                    goto fail;
                }
                if (!aget(env, static_cast<jarray>(regs[arr].o), regs[idx].i, kind, &regs[dst])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        release_stash(env, &stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_APUT: {
                if (pc + 4 > code_size) goto fail;
                uint8_t src = code[pc++];
                uint8_t arr = code[pc++];
                uint8_t idx = code[pc++];
                uint8_t kind = code[pc++];
                if (!reg_bounds(src, regs.size()) || !reg_bounds(arr, regs.size()) ||
                    !reg_bounds(idx, regs.size())) {
                    goto fail;
                }
                if (!aput(env, static_cast<jarray>(regs[arr].o), regs[idx].i, kind, regs[src])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        release_stash(env, &stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_CHECK_CAST: {
                if (pc + 3 > code_size) goto fail;
                uint8_t obj = code[pc++];
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(obj, regs.size()) || tid >= img.types.size()) goto fail;
                if (regs[obj].o != nullptr) {
                    jclass cls = find_class_desc(env, img.types[tid]);
                    if (cls == nullptr) goto fail;
                    if (!env->IsInstanceOf(regs[obj].o, cls)) {
                        throw_cce(env, "PVM2 check-cast");
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        release_stash(env, &stashed_exception);
                        return nullptr;
                    }
                }
                break;
            }
            case OP_INSTANCE_OF: {
                if (pc + 4 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t obj = code[pc++];
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(obj, regs.size()) ||
                    tid >= img.types.size()) {
                    goto fail;
                }
                // Compute before reg_as_i — dst may alias obj (instance-of v0, v0, T).
                int32_t is_inst = 0;
                if (regs[obj].o != nullptr) {
                    jclass cls = find_class_desc(env, img.types[tid]);
                    if (cls == nullptr) goto fail;
                    is_inst = env->IsInstanceOf(regs[obj].o, cls) ? 1 : 0;
                }
                reg_as_i(env, &regs[dst]);
                regs[dst].i = is_inst;
                break;
            }
            case OP_THROW: {
                if (pc + 1 > code_size) goto fail;
                uint8_t src = code[pc++];
                if (!reg_bounds(src, regs.size()) || regs[src].o == nullptr) goto fail;
                env->Throw(static_cast<jthrowable>(regs[src].o));
                if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                    break;
                }
                clear_regs(env, regs);
                release_stash(env, &stashed_exception);
                return nullptr;
            }
            case OP_MOVE_EXCEPTION: {
                if (pc + 1 > code_size) goto fail;
                uint8_t dst = code[pc++];
                if (!reg_bounds(dst, regs.size()) || stashed_exception == nullptr) goto fail;
                // Transfer stash ownership — avoid NewLocalRef+Delete alias on OEM ART.
                jobject held = stashed_exception;
                stashed_exception = nullptr;
                reg_take_o(env, &regs[dst], held, false);
                break;
            }
            case OP_CONST_CLASS: {
                if (pc + 3 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(dst, regs.size()) || tid >= img.types.size()) goto fail;
                jclass cls = find_class_desc(env, img.types[tid]);
                if (cls == nullptr) goto fail;
                bool g = false;
                jobject copy = dup_owned_ref(env, cls, &g);
                reg_take_o(env, &regs[dst], copy, g);
                break;
            }
            case OP_NEG: {
                if (pc + 2 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(src, regs.size())) goto fail;
                int32_t v = -regs[src].i;
                reg_as_i(env, &regs[dst]);
                regs[dst].i = v;
                break;
            }
            default:
                PLOGE("PVM2 unknown op 0x%02x pc=%zu", op, fault_pc);
                goto fail;
        }
    }

    clear_pending(env, pending);
    clear_regs(env, regs);
    release_stash(env, &stashed_exception);
    if (!finished) {
        if (result_is_global && result != nullptr) {
            env->DeleteGlobalRef(result);
        }
        throw_runtime(env, "VMP fell off end");
        return nullptr;
    }
    if (result_is_global && result != nullptr) {
        jobject local = env->NewLocalRef(result);
        env->DeleteGlobalRef(result);
        return local;
    }
    return result;

fail:
    clear_pending(env, pending);
    clear_regs(env, regs);
    release_stash(env, &stashed_exception);
    if (result_is_global && result != nullptr) {
        env->DeleteGlobalRef(result);
        result = nullptr;
    }
    if (!env->ExceptionCheck()) {
        throw_runtime(env, "VMP interpret error");
    }
    return nullptr;
}

/** Multi-ISA entry points (separate .bitcode symbols) — Phase 3. */
PROTECTOR_ENCRYPT static jobject pvm2_run_a(JNIEnv* env, int dex_index, uint32_t method_idx,
                                            jobjectArray args) {
    return interpret_body(env, dex_index, method_idx, args);
}

PROTECTOR_ENCRYPT static jobject pvm2_run_b(JNIEnv* env, int dex_index, uint32_t method_idx,
                                            jobjectArray args) {
    return interpret_body(env, dex_index, method_idx, args);
}

PROTECTOR_ENCRYPT static jobject pvm2_run_c(JNIEnv* env, int dex_index, uint32_t method_idx,
                                            jobjectArray args) {
    return interpret_body(env, dex_index, method_idx, args);
}

static uint8_t peek_isa_id(const std::vector<uint8_t>& image) {
    if (image.size() < 16) {
        return 0;
    }
    uint16_t ver = static_cast<uint16_t>(image[4] | (image[5] << 8));
    if (ver < PVM2_VERSION_V3) {
        return 0;
    }
    return image[15];
}

PROTECTOR_ENCRYPT jobject interpret(JNIEnv* env, int dex_index, uint32_t method_idx,
                                    jobjectArray args) {
    if (!risk::vmp_allowed()) {
        clear_true_vmp_lru();
        throw_security(env, "VMP refused by RASP");
        return nullptr;
    }
    auto& state = runtime_state();
    auto dex_it = state.code_map.find(dex_index);
    if (dex_it == state.code_map.end()) {
        throw_runtime(env, "VMP bad dex");
        return nullptr;
    }
    auto m_it = dex_it->second.find(method_idx);
    if (m_it == dex_it->second.end() || m_it->second == nullptr
            || (m_it->second->flags & FLAG_TRUE_VMP) == 0) {
        throw_runtime(env, "VMP bad method");
        return nullptr;
    }
    CodeItem* item = m_it->second;
    VmpUsePin pin;
    {
        std::lock_guard<std::mutex> lock(item->parse_mu);
        if (!ensure_true_vmp_plaintext_locked(item)) {
            throw_runtime(env, "VMP not ready");
            return nullptr;
        }
        pin.acquire(item);
    }
    lru_touch(item);
    uint8_t isa = peek_isa_id(item->vm_image);
    switch (isa % PVM2_ISA_COUNT) {
        case 1:
            return pvm2_run_b(env, dex_index, method_idx, args);
        case 2:
            return pvm2_run_c(env, dex_index, method_idx, args);
        default:
            return pvm2_run_a(env, dex_index, method_idx, args);
    }
}

} // namespace protector::vm
