#include "spk.h"
#include <iostream>

int main() {
    // Guard the explicitly unavailable legacy proof path without invoking its
    // unsafe signing/ownership code. No PBC elements are dereferenced by verify.
    const SPKProof empty{};
    if (SPK::verify(empty)) {
        std::cerr << "Unimplemented legacy verifier accepted an empty proof\n";
        return 1;
    }
    return 0;
}
