#include "lktrs.h"
#include <iostream>

void LkTRS::hash_to_Zp(element_t result, const std::string& input) {
    // 使用输入字符串的简单哈希
    unsigned char hash[32] = {0};  // 用于存储哈希值

    // 一个简单的哈希实现
    for(size_t i = 0; i < input.length(); i++) {
        hash[i % 32] ^= input[i];
    }

    // 初始化为Zr中的元素
    element_init_Zr(result, pairing);

    // 将哈希值转换为大整数
    mpz_t z;
    mpz_init(z);
    mpz_import(z, 32, 1, 1, 0, 0, hash);

    // 将大整数转换为Zr中的元素
    element_set_mpz(result, z);

    mpz_clear(z);
}

void LkTRS::hash_to_Gp(element_t result, const std::string& input) {
    // 首先哈希到Zr
    element_t h;
    element_init_Zr(h, pairing);
    hash_to_Zp(h, input);

    // 初始化G1中的结果元素
    element_init_G1(result, pairing);

    // 使用生成元g来创建G1中的元素
    element_pow_zn(result, g, h);  // result = g^h

    element_clear(h);
}

// Constructor implementation
LkTRS::LkTRS(const char* param_str, int max_signs) {
    this->param_str = param_str;

    pairing_init_set_str(pairing, param_str);
    k = max_signs;

    element_init_G1(g, pairing);
    element_init_G2(h, pairing);
    element_init_G1(u, pairing);
    element_init_G1(g0, pairing);
    element_init_G1(g1, pairing);
    element_init_G1(g2, pairing);
    element_init_G1(u_t, pairing);

    mpz_init(p);
}

// Destructor implementation
LkTRS::~LkTRS() {
    if(acc) {
        delete acc;
        acc = nullptr;
    }

    element_clear(g);
    element_clear(h);
    element_clear(u);
    element_clear(g0);
    element_clear(g1);
    element_clear(g2);
    element_clear(u_t);
    mpz_clear(p);
    pairing_clear(pairing);
}

// Setup implementation
bool LkTRS::Setup(size_t lambda) {
    // Generate random generators
    element_random(g);
    element_random(h);
    element_random(u);

    // Generate random elements in G1
    element_random(g0);
    element_random(g1);
    element_random(g2);

    // Compute u_t = H'(issue)
    hash_to_Gp(u_t, issue);

    return true;
}

// KeyGen implementation
std::pair<PublicKey, SecretKey> LkTRS::KeyGen() {
    PublicKey pk;
    SecretKey sk;

    // Initialize elements
    element_init_Zr(sk.x_i, pairing);
    element_init_G1(pk.u_i, pairing);
    element_init_G1(pk.y_i, pairing);
    element_init_Zr(sk.s_i, pairing);
    element_init_Zr(sk.t_i, pairing);

    // Generate secret key x_i
    element_random(sk.x_i);

    // Generate random u_i and compute y_i
    element_random(pk.u_i);
    element_pow_zn(pk.y_i, pk.u_i, sk.x_i);

    // Compute s_i and t_i
    std::string x_i_str = ""; // Convert x_i to string
    hash_to_Zp(sk.s_i, x_i_str + issue + "0");
    hash_to_Zp(sk.t_i, x_i_str + issue + "1");

    return std::make_pair(pk, sk);
}

void LkTRS::updateIssue(const std::string& new_issue) {
    issue = new_issue;
}

bool LkTRS::Join(PublicKey& pk_j, Signature& sigma,
                 element_t& V_out, element_t& w_i_out) {
    if(!acc) {
        acc = new Accumulator(param_str);
        acc->set_generator(g);
    }
    // Add the new user's public key to the accumulator
    try {
        acc->set_accumulator_value(sigma.V);
        acc->add_user(pk_j.u_i);
        acc->get_accumulator_value(V_out);
        acc->get_witness(pk_j.u_i, w_i_out);
    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return false;
    }
    return true;
}

bool LkTRS::Exit(PublicKey& pk_j, Signature& sigma,
                 element_t& V_out) {
    if(!acc) {
        acc = new Accumulator(param_str);
        acc->set_generator(g);
    }
    // Remove the user's public key from the accumulator
    try {
        acc->set_accumulator_value(sigma.V);
        acc->remove_user(pk_j.u_i);
        acc->get_accumulator_value(V_out);
    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return false;
    }
    return true;
}

bool LkTRS::Link(const std::string& m1, const element_t nym1, const Signature& sigma1,
                 const std::string& m2, const element_t nym2, const Signature& sigma2) {
    // simply check if the presudonyms are the same
    return nym1 == nym2;
}

PublicKey LkTRS::kTrace(element_t nym1, element_t nym2, 
                               std::string& m1, Signature& sigma1,
                               std::string& m2, Signature& sigma2) { 
    // Step 1: If the pseudonyms are different, return an invalid public key
    if (element_cmp(nym1, nym2) != 0) {
        return PublicKey();  // Return an empty PublicKey as an indication of invalid case
    }

    // Step 2: Check if the signature components are different (S1 != S2)
    if (element_cmp(sigma1.S, sigma2.S) != 0) {
        // Signatures have not exceeded the usage limit, return "legal"
        return PublicKey();  // Return an empty PublicKey for legal cases
    }

    // Step 3: If S1 == S2, calculate the public key of the signer and trace it
    // Compute y_i using the formula y_i = ((T1^R2) / (T2^R1)) ^ (R2 - R1)^(-1)
    element_t y_i;
    element_init_G1(y_i, pairing);

    // First, compute the intermediate values (T1^R2) and (T2^R1)
    element_t term1, term2, inv_R_diff;
    element_init_G1(term1, pairing);
    element_init_G1(term2, pairing);
    element_init_Zr(inv_R_diff, pairing);

    // Compute (T1^R2)
    element_pow_zn(term1, sigma1.T, sigma2.R);  // T1^R2
    // Compute (T2^R1)
    element_pow_zn(term2, sigma2.T, sigma1.R);  // T2^R1

    // Compute (R2 - R1)^(-1)
    element_sub(inv_R_diff, sigma2.R, sigma1.R);  // R2 - R1
    element_invert(inv_R_diff, inv_R_diff);  // (R2 - R1)^(-1)

    // Compute y_i = ((T1^R2) / (T2^R1))^(R2 - R1)^(-1)
    element_div(term1, term1, term2);  // (T1^R2) / (T2^R1)
    element_pow_zn(y_i, term1, inv_R_diff);  // y_i = ((T1^R2) / (T2^R1)) ^ (R2 - R1)^(-1)

    // Clean up intermediate elements
    element_clear(term1);
    element_clear(term2);
    element_clear(inv_R_diff);

    // Step 4: Return the public key (u_i, y_i)
    // PublicKey contains the user public key and computed y_i
    PublicKey pk;
    element_set(pk.y_i, y_i); // u_i here is random
    return pk;
}

void LkTRS::compute_accumulator(element_t result, std::vector<PublicKey>& L) {
    element_init_G1(result, pairing);
    element_set1(result); // Set to identity element
    
    element_t temp;
    element_init_G1(temp, pairing);
    
    for(auto& pk : L) {
        element_mul(result, result, pk.u_i);
    }
    
    element_clear(temp);
}

// compute_witness 函数实现
void LkTRS::compute_witness(element_t result, std::vector<PublicKey>& L, PublicKey& pk_i) {
    element_init_G1(result, pairing);
    element_set1(result); // 初始化为单位元
    
    element_t temp;
    element_init_G1(temp, pairing);
    
    // 计算除了 pk_i 之外所有公钥的乘积
    for(auto& pk : L) {
        if (!element_cmp(pk.u_i, pk_i.u_i)) { // 如果不是当前公钥
            continue;
        }
        element_mul(result, result, pk.u_i);
    }
    
    element_clear(temp);
}

bool LkTRS::is_valid_group_element(element_t e) {
    // 检查元素是否为单位元
    if (element_is1(e)) return false;
    
    // 检查元素是否为零
    if (element_is0(e)) return false;
    
    // 额外的群元素验证：e^q 应该等于 1，其中 q 是群的阶
    element_t temp, result;
    element_init_G1(temp, pairing);
    element_init_GT(result, pairing);
    
    // 获取群的阶
    element_t order;
    element_init_Zr(order, pairing);
    element_set_str(order, "r", 10); // 使用群的阶，这里需要根据你的参数设置
    
    // 计算 e^q
    element_pow_zn(temp, e, order);
    
    bool is_valid = element_is1(temp);
    
    element_clear(temp);
    element_clear(result);
    element_clear(order);
    
    return is_valid;
}

LkTRS::Signature LkTRS::RSign(SecretKey& sk_i,
                              PublicKey& pk_i,
                              std::vector<PublicKey>& L,
                              std::string& message,
                              int cnt_i,
                              element_t& nym_out) {
    Signature sigma;
    
    // 初始化签名组件
    element_init_G1(sigma.V, pairing);
    element_init_G1(sigma.S, pairing);
    element_init_G1(sigma.T, pairing);
    element_init_Zr(sigma.R, pairing);
    
    // 计算一次性匿名标识符 (nym)
    element_init_G1(nym_out, pairing);
    element_t r;
    element_init_Zr(r, pairing);
    element_random(r);  // 随机选择 r
    element_pow_zn(nym_out, g, r);  // nym = g^r
    
    // 计算累加器值 V
    compute_accumulator(sigma.V, L);
    
    // 计算一次性通行证 S
    element_t temp;
    element_init_G1(temp, pairing);
    element_pow_zn(temp, g, sk_i.s_i);  // g^s_i
    element_pow_zn(sigma.S, h, r);      // h^r
    element_mul(sigma.S, sigma.S, temp); // S = g^s_i * h^r
    
    // 计算追踪标签 T
    element_pow_zn(sigma.T, g, sk_i.t_i);  // T = g^t_i
    
    // 生成随机挑战 R (在实际应用中这应该是基于消息和其他参数的哈希)
    element_random(sigma.R);
    
    // 这里应该生成 SPK，但我们暂时将其作为抽象接口处理
    // SPK would prove knowledge of (s_i, t_i, r) satisfying:
    // 1. S = g^s_i * h^r
    // 2. T = g^t_i
    // 3. nym = g^r
    // 4. V contains u_i
    SPK spk(&sk_i, &pk_i, cnt_i, pairing);
    sigma.spk_proof = spk.genProof(); // todo
    
    // 清理临时变量
    element_clear(r);
    element_clear(temp);
    
    return sigma;
}

bool LkTRS::RVer(std::vector<PublicKey>& L,
                 std::string& message,
                 element_t nym,
                 Signature& sigma) {
    // 验证累加器值
    element_t computed_V;
    compute_accumulator(computed_V, L);
    
    // 累加器值不对应 验证失败
    if (element_cmp(computed_V, sigma.V) != 0) {
        element_clear(computed_V);
        return false;
    }
    
    // 验证签名组件是否为有效的群元素
    if (!is_valid_group_element(sigma.S) || 
        !is_valid_group_element(sigma.T) || 
        !is_valid_group_element(nym)) {
        element_clear(computed_V);
        return false;
    }
    
    // 这里应该验证 SPK，但我们暂时将其作为抽象接口处理
    // SPK would verify:
    // 1. S is properly formed
    // 2. T is properly formed
    // 3. nym is properly formed
    // 4. The prover knows the discrete logarithms
    // 5. The values are consistent with V
    bool result = SPK::verify(sigma.spk_proof); // todo
    
    element_clear(computed_V);
    return result;
}
