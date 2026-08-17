# Lab 03 — The debugging challenge

**Difficulty:** Intermediate
**Time:** 2–4 hours
**Prerequisites:** [Lab 01](lab-01-first-program-all-the-way-down.md),
[Chapter 03 §3.4, §3.7.4, §3.13, §3.17, §7.1](../README.md)

---

## Objective

Six programs. Each contains **exactly one** planted bug. Find them all, and — more importantly — find
them with a *method* rather than by staring.

Time yourself on each one. Record which technique found it. At the end you will have data about your
own debugging, which is far more useful than a general sense that you are "quite good at it".

> **🧠 Mental Model — quit thinking and look.** The most expensive debugging habit is reasoning about
> what the code *should* do instead of observing what it *does*. Every technique in this lab is a way
> of looking: printing a value, stopping at a line, halving the search space, letting the compiler
> tell you. When you catch yourself thinking "but that can't be happening", that is the moment to
> stop thinking and put a breakpoint on it.

---

## Rules

- No reading the solutions until you have genuinely tried.
- **Record your time and your method for each bug.** The data is the deliverable.
- For each bug, before you fix it, write down: *what is the observed symptom, and what is the
  mechanism?* Those are different sentences and beginners conflate them.
- After fixing, write the **regression test** that would have caught it. Every one of these bugs is
  catchable by a five-line test.

---

## Setup

```bash
# host
mkdir -p ~/lab03 && cd ~/lab03
cp ../examples/debug-challenge/* .    # or type them from the listings below
gcc --version && python3 --version && javac -version
```

The full source of all six is in
[`../examples/debug-challenge/`](../examples/debug-challenge/).

---

## Bug 1 — Off by one (C)

**Difficulty:** ★☆☆☆☆ — the warm-up.

```c
/* bug1.c — build: gcc -O0 -g bug1.c -o bug1 */
#include <stdio.h>

int sum_array(const int *arr, int len) {
    int total = 0;
    for (int i = 0; i <= len; i++) {     /* reads arr[len] */
        total += arr[i];
    }
    return total;
}

int main(void) {
    int data[5] = {1, 2, 3, 4, 5};
    printf("sum = %d\n", sum_array(data, 5));   /* should be 15 */
    return 0;
}
```

**Symptom:** the answer is wrong, sometimes. Sometimes it is right. Sometimes it crashes.

**Q1.** Run it ten times. Is the output stable? Explain why the behaviour is inconsistent — what is
being read on the last iteration, and who owns that memory?

**Q2.** Find it with a tool rather than by reading:

```bash
# host
gcc -fsanitize=address -g bug1.c -o bug1_asan && ./bug1_asan
```

How long did that take compared with reading the loop?

**Q3.** Why is this a **security** bug and not just a correctness bug? What if `arr` were a
stack-allocated buffer immediately below the saved return address?

---

## Bug 2 — Integer overflow (C)

**Difficulty:** ★★☆☆☆

```c
/* bug2.c — build: gcc -O0 -g bug2.c -o bug2 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Allocates space for `count` records of 16 bytes each and copies them in. */
char *load_records(const char *src, int count) {
    int size = count * 16;
    char *buf = malloc(size);
    if (!buf) return NULL;
    memcpy(buf, src, count * 16);
    return buf;
}

int main(int argc, char **argv) {
    int count = (argc > 1) ? atoi(argv[1]) : 4;
    char src[8192];
    memset(src, 'A', sizeof(src));

    char *r = load_records(src, count);
    printf("loaded %d records -> %p\n", count, (void *)r);
    free(r);
    return 0;
}
```

**Symptom:** works fine for normal values. `./bug2 4` prints an address. `./bug2 200000000` does
something unexpected.

**Q4.** Run it with 4, then with 200000000, then with 134217729. Describe each outcome.

**Q5.** Use a debugger to see the value directly:

```bash
# host
gdb ./bug2
(gdb) break load_records
(gdb) run 200000000
(gdb) next
(gdb) print size
(gdb) print (unsigned long)size
```

What is `size`? What does `malloc` actually receive?

**Q6.** Now use the sanitiser:

```bash
# host
gcc -fsanitize=undefined,address -g bug2.c -o bug2_san && ./bug2_san 200000000
```

Which line and column did it name?

**Q7.** Write the fix. Then write a one-sentence severity assessment, and say what additional fact
you would need before you could rate it in a real report.

---

## Bug 3 — Use after free (C)

**Difficulty:** ★★★☆☆

```c
/* bug3.c — build: gcc -O0 -g bug3.c -o bug3 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char name[32]; int admin; } session_t;

session_t *make_session(const char *name, int admin) {
    session_t *s = malloc(sizeof(session_t));
    strncpy(s->name, name, sizeof(s->name) - 1);
    s->name[sizeof(s->name) - 1] = '\0';
    s->admin = admin;
    return s;
}

void logout(session_t *s) {
    printf("logging out %s\n", s->name);
    free(s);
}

int main(void) {
    session_t *s = make_session("alice", 0);
    logout(s);

    /* Something else allocates the same block. */
    session_t *attacker = make_session("mallory", 1);
    (void)attacker;

    /* And the old pointer is still used. */
    printf("admin flag for %s is %d\n", s->name, s->admin);
    return 0;
}
```

**Symptom:** the final line prints the wrong name, and — worse — the wrong admin flag.

**Q8.** What does the program print? Explain the mechanism in terms of the allocator: why did the
second `malloc` return the same address?

**Q9.** Find it with a tool:

```bash
# host
gcc -fsanitize=address -g bug3.c -o bug3_asan && ./bug3_asan
```

ASan prints "freed by thread T0 here" and "previously allocated by thread T0 here". Which two source
lines does it name, and why are *both* needed to understand the bug?

**Q10.** This one is a privilege escalation, not a crash. Explain how an attacker who controls what
gets allocated after the free turns this into "become admin".

**Q11.** Which single line is the actual fix? (There are three defensible answers; pick one and
defend it.)

---

## Bug 4 — Reference versus value (Java)

**Difficulty:** ★★☆☆☆ — and it catches experienced people.

```java
// Bug4.java — build: javac Bug4.java && java Bug4
import java.util.*;

public class Bug4 {

    static void addDefaults(List<String> roles) {
        roles = new ArrayList<>(roles);   // "defensive copy"
        roles.add("user");
    }

    static void promote(StringBuilder role) {
        role.append("-admin");
    }

    public static void main(String[] args) {
        List<String> roles = new ArrayList<>();
        roles.add("guest");
        addDefaults(roles);
        System.out.println("roles = " + roles);       // expected [guest, user]

        StringBuilder r = new StringBuilder("editor");
        promote(r);
        System.out.println("role = " + r);            // expected editor
    }
}
```

**Symptom:** both lines print the opposite of what the developer expected. `addDefaults` does not add
anything; `promote` modifies the caller's object.

**Q12.** Explain each result. Use the phrase "Java is always pass by value, and for objects the value
copied is the reference."

**Q13.** Why does reassigning the parameter in `addDefaults` have no effect on the caller, while
mutating the object in `promote` does?

**Q14.** Turn this into a security scenario: a function receives a `byte[]` of key material, and
"clears" it by writing `key = new byte[32]`. What actually happened to the original key material?

---

## Bug 5 — The silent swallow (Java)

**Difficulty:** ★★★☆☆ — the hardest to find, because nothing looks wrong.

```java
// Bug5.java
import java.security.MessageDigest;
import java.util.Arrays;

public class Bug5 {

    /** Returns true if the supplied MAC matches the expected one. */
    static boolean verify(byte[] data, byte[] providedMac, byte[] key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(key);
            md.update(data);
            byte[] expected = md.digest();
            return Arrays.equals(expected, providedMac);
        } catch (Exception e) {
            // Should never happen — SHA-256 is always available.
        }
        return true;
    }

    public static void main(String[] args) {
        byte[] key  = "secret".getBytes();
        byte[] data = "transfer 100".getBytes();
        byte[] bad  = new byte[32];
        System.out.println("bad MAC accepted? " + verify(data, bad, key));
    }
}
```

**Symptom:** none, under normal conditions. The function works. Tests pass.

**Q15.** Find the bug by reading. There are actually **two** here — one that fires only in an error
path, and one that is always present. Name both.

**Q16.** Prove the first one. Change `"SHA-256"` to `"SHA-256-NONEXISTENT"` and run it. What happens,
and why is that catastrophic?

**Q17.** The second bug is `Arrays.equals`. Why is it the wrong function for comparing a MAC, and what
should be used instead? (Search for "timing attack" and "constant time comparison".)

**Q18.** Write the corrected function. Then write the code-review rule that would have caught the
first bug in any file, and the `grep` that finds candidates:

```bash
# host — your answer here
grep -rn 'catch *(.*) *{ *}' src/
```

---

## Bug 6 — The one that only fires sometimes (Python)

**Difficulty:** ★★★★☆

```python
# bug6.py — run: python3 bug6.py
import random

def allocate_slots(requests, capacity=100):
    """Distributes `capacity` slots across requests, proportionally."""
    total = sum(r["weight"] for r in requests)
    assigned = []
    remaining = capacity
    for r in requests:
        share = int(capacity * r["weight"] / total)
        assigned.append({"id": r["id"], "slots": share})
        remaining -= share
    # Give any leftover to the first request.
    assigned[0]["slots"] += remaining
    return assigned

def check(requests):
    result = allocate_slots(requests)
    total = sum(a["slots"] for a in result)
    assert total == 100, f"allocated {total}, expected 100: {result}"
    for a in result:
        assert a["slots"] >= 0, f"negative allocation: {a}"

if __name__ == "__main__":
    random.seed()
    for trial in range(10000):
        n = random.randint(1, 8)
        reqs = [{"id": i, "weight": random.randint(0, 50)} for i in range(n)]
        try:
            check(reqs)
        except Exception as e:
            print(f"FAILED on trial {trial}: {e}")
            print(f"  input: {reqs}")
            break
    else:
        print("10000 trials passed")
```

**Symptom:** passes most of the time. Occasionally throws. The failing input is different every run.

**Q19.** Run it several times. What exception appears, and what is the failing input?

**Q20.** This is a **bisection** problem, not a reading problem. The failing input is random, so first
make it reproducible:

```python
# add at the top of main
SEED = 12345
random.seed(SEED)
```

Once it fails deterministically, shrink the input by hand: can you find a two-element input that
fails? A one-element input?

**Q21.** What is the root cause? (There is more than one path to failure. Find at least two.)

**Q22.** Why did 10 000 random trials find it, when reading the eight-line function did not? Write one
sentence about what that implies for how you should test parsers.

---

## Part 2 — Your data

Fill this in as you go. It is the actual deliverable.

| Bug | Language | Time to find | Technique that found it | Technique you tried first |
|---|---|---|---|---|
| 1 — off by one | C | | | |
| 2 — integer overflow | C | | | |
| 3 — use after free | C | | | |
| 4 — reference vs value | Java | | | |
| 5 — silent swallow | Java | | | |
| 6 — intermittent | Python | | | |

**Q23.** Look at your "technique you tried first" column. How often was it reading the code? How often
did reading actually find it?

**Q24.** Which bug took longest? Which technique would have found it fastest, in hindsight?

---

## Part 3 — Write the tests

For each bug, write a test that fails before the fix and passes after. This converts six exercises
into six permanent controls.

```c
/* Example for bug 1 — a test with a guard value */
void test_sum_array_does_not_overread(void) {
    int data[6] = {1, 2, 3, 4, 5, 0xDEADBEEF};
    assert(sum_array(data, 5) == 15);   /* fails if arr[5] is included */
}
```

**Q25.** Which of the six bugs is hardest to write a test for, and why? What would you do instead for
that one? (Hint: for bug 6, the answer is not a test — it is a *fuzzer*, or property-based testing.)

---

## Success criteria

- [ ] All six bugs found
- [ ] For each: the symptom and the mechanism written as separate sentences
- [ ] Sanitisers used on bugs 1, 2 and 3, and the exact reported line recorded
- [ ] A debugger used on at least two bugs, with a `print` of the offending value
- [ ] Bug 6 made deterministic with a fixed seed, then minimised by hand
- [ ] The timing/technique table filled in
- [ ] A regression test written for at least five of the six
- [ ] You can state which technique has the best time-to-find per unit of effort, from your own data

---

## Debrief

1. Rank the six techniques you used — reading, printing, breakpoints, watchpoints, sanitisers,
   bisection, fuzzing — by how much time each saved you *in this lab*. Does the ranking match your
   intuition before you started?
2. Bugs 1, 2 and 3 were all found in seconds by a sanitiser. Why do you think most codebases do not
   have sanitisers enabled in CI?
3. Bug 5 has no symptom under normal operation. What class of bug does that describe, and how do you
   find them at all?
4. Bug 4 is not a memory-safety bug and Java did not protect against it. What *kind* of bug is it, and
   what would protect against it?
5. Bug 6 was found by 10 000 random inputs. Generalise that: which of the other five would random
   input have found, and which would it have missed?
6. For each of the six, name the section of [chapter 03](../README.md) that describes the underlying
   construct.
7. You are handed an unfamiliar codebase and told "there is a bug somewhere, users report occasional
   wrong balances". Describe your first hour, using this lab's techniques in order.

---

## Where this goes next

[Lab 04](lab-04-reading-unfamiliar-code.md) removes the safety net entirely: no planted bugs, no
listing on the page, and a codebase nobody wrote for you. It is the one that matters most.
