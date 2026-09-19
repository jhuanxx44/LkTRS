#ifndef LKTRS_H
#define LKTRS_H

#include <gmp.h>
#include <pbc/pbc.h>
#include <string>
#include <vector>
#include <map>
#include <utility>
#include "pp.h"
#include "accumulator.h"
#include "spk.h"

class LkTRS {
private:
    // PBC parameters
    const char* param_str;

    // System parameters
    pairing_t pairing;
    element_t g, h, u;        // Generators
    element_t g0, g1, g2;     // Random elements in G1
    element_t u_t;            // H'(issue)
    mpz_t p;                  // Prime order
    std::string issue;        // Current transaction round
    int k;                    // Maximum signing times

    // Accumulator
    Accumulator* acc = nullptr;

    // Helper functions
    void hash_to_Zp(element_t result, const std::string& input);
    void hash_to_Gp(element_t result, const std::string& input);

public:
    struct Signature {
        element_t V;          // Accumulator value
        element_t S;          // One-time pass
        element_t T;          // Tracing tag
        element_t R;          // Challenge
        SPKProof spk_proof;   // Signature Proof of Knowledge (like ZK proof)
    };

    // Constructor
    LkTRS(const char* param_str, int max_signs);
    ~LkTRS();

    // Main interface methods
    bool Setup(size_t lambda);

    std::pair<PublicKey, SecretKey> KeyGen();

    void updateIssue(const std::string& new_issue);

    bool Join(PublicKey& pk_j, Signature& sigma,
              element_t& V_out, element_t& w_i_out);

    bool Exit(PublicKey& pk_j, Signature& sigma,
              element_t& V_out);

    Signature RSign(SecretKey& sk_i,
                    PublicKey& pk_i,
                    std::vector<PublicKey>& L,
                    std::string& message,
                    int cnt_i,
                    element_t& nym_out);

    bool RVer(std::vector<PublicKey>& L,
              std::string& message,
              element_t nym,
              Signature& sigma);

    bool Link(const std::string& m1, const element_t nym1, const Signature& sigma1,
              const std::string& m2, const element_t nym2, const Signature& sigma2);

    PublicKey kTrace(element_t nym1, element_t nym2, 
                     std::string& m1, Signature& sigma1,
                     std::string& m2, Signature& sigma2);

private:
    // Helper method
    bool is_valid_group_element(element_t e);

    // Helper method to compute accumulator
    void compute_accumulator(element_t result, std::vector<PublicKey>& pks);

    // Helper method to compute witness
    void compute_witness(element_t result, std::vector<PublicKey>& pks,
                         PublicKey& excluded_pk);
};

#endif