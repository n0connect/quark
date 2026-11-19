#pragma once
// Single funnel for every failure path in DRM_Wrapper. Each call site passes
// a specific quark::error::Code identifying *what* went wrong; FailDeadly
// reports it (one line to debug-crash.txt, one line to the terminal if
// attached -- see quark/error.hpp) and then terminates, unconditionally and
// identically, no matter which code came in.
//
// This is a deliberate, explicit broadening of CLAUDE.md rule 5's original
// "no diagnostic message" wording -- requested so field crashes are
// debuggable -- but the rule's actual point survives untouched: there is
// still exactly one outward *behavior* (report, then exit(1), no recovery,
// no branch), and a reviewer still only has one place to audit. What changed
// is that the single behavior now also says, in one numbered word, why.

#include <cstdlib>

#include "quark/error.hpp"

namespace quark::drm_wrapper {

[[noreturn]] inline void FailDeadly(quark::error::Code code, const char* detail = nullptr) {
    quark::error::Report(code, "DRM_Wrapper", detail);
    // `std::exit` runs static destructors (good -- lets ScopedZero guards
    // clear key material before the process actually goes away).
    std::exit(1);
}

}  // namespace quark::drm_wrapper
