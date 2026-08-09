// Copyright 2026 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for that specific language governing permissions and
// limitations under the License.

// Android-only workaround for a dynamic-symbol collision between AWS-LC and
// React Native.
//
// AWS-LC (pulled in via `rustls-aws-lc-rs` -> `aws-lc-sys`) wants to use
// jemalloc's sized-free when it happens to be present, so `crypto/mem.c`
// declares it as a weak *function*:
//
//     WEAK_SYMBOL_FUNC(void, sdallocx, (void *ptr, size_t size, int flags))
//
// and then guards every use with a null check:
//
//     if (sdallocx) {
//       sdallocx(ptr, size + OPENSSL_MALLOC_PREFIX, 0);
//     } else {
//       free(ptr);
//     }
//
// The comment above that declaration assumes an unresolved weak symbol stays
// NULL unless a malloc implementation is *statically* linked in. That does not
// hold on Android: `libreactnative.so` and `libjsi.so` both export `sdallocx`
// (along with `mallocx` and `nallocx`) as an 8-byte **data object** in `.bss`,
// and they are loaded into the global group before this library. The dynamic
// linker therefore resolves our weak undefined function reference to the
// *address of that variable*. The null check passes, AWS-LC calls it, and the
// PLT stub branches into a non-executable `rw-` page:
//
//     signal 11 (SIGSEGV), code 2 (SEGV_ACCERR)
//     #00 pc 0x6290 [anon:.bss]
//     #11 pc ...    libc.so (pthread_once+148)
//
// Defining `sdallocx` here with hidden visibility resolves AWS-LC's reference
// at static-link time to a real function. Hidden visibility is what makes this
// work: the symbol is non-preemptible, so it is bound directly, no
// R_AARCH64_JUMP_SLOT relocation is emitted, no entry lands in `.dynsym`, and
// the definitions in React Native's libraries are never consulted.
//
// Behaviourally this is a no-op: it is exactly the `else` branch AWS-LC takes
// when the symbol is absent, called with the same pointer.

#include <stdlib.h>

__attribute__((visibility("hidden"))) void sdallocx(void *ptr, size_t size, int flags) {
    // The size/flags hints only matter to a real jemalloc; plain `free` is what
    // AWS-LC falls back to when `sdallocx` is unavailable.
    (void)size;
    (void)flags;
    free(ptr);
}
