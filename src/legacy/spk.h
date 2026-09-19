#ifndef SPK_H
#define SPK_H

#include <gmp.h>
#include <pbc/pbc.h>
#include "pp.h"

/*
Signature Proof of Knowledge (SPK) \cite{chase2006SoK} 
is a protocol that allows a prover to demonstrate knowledge 
of a digital signature on a message, without revealing the 
actual signature or the private key used to create it. 

It provides a way to convince a verifier that the prover 
possesses the private key corresponding to a specific digital 
signature, while maintaining the confidentiality and integrity
of the private key.

Note: this can be replaced by other ZK tools
*/

struct SPKProof {
    element_t c;
    element_t z;
};

class SPK {
    // secret things: xi, si, ti, yi, cnti
    SecretKey* sk; // xi, si, ti
    PublicKey* pk; // yi 
    int cnt;      // cnti
    // witness: wi
    element_t w;
public:
    SPK();
    SPK(SecretKey* sk, PublicKey* pk, int cnt, pairing_t pairing);
    SPKProof genProof(); // TODO
    static bool verify(const SPKProof &p); // TODO. Note that this function is parameters irrelevant
    ~SPK();
};

#endif