#include "accumulator.h"

// 初始化累加器，选择曲线参数
Accumulator::Accumulator(const char* param_str) {
    pairing_init_set_str(pairing, param_str);
    // 初始化累加器值 u 和初始累加器 V
    element_init_G1(u, pairing);
    element_random(u);  // 随机生成元素 u
    element_init_G1(V, pairing);
    element_set1(V);  // 初始值为单位元
}

void Accumulator::set_generator(element_t &g) {
    element_set(u, g);
}

// 增加用户，将 x 加入累加器
void Accumulator::add_user(element_t &x) {
    element_t temp;
    element_init_G1(temp, pairing);
    element_pow_zn(temp, u, x);  // f_acc(u, x) = u^x
    element_mul(V, V, temp);     // 更新 V = V * f_acc(u, x)
    element_clear(temp);
}

// 减少用户，从累加器中移除 x
void Accumulator::remove_user(element_t &x) {
    element_t temp;
    element_init_G1(temp, pairing);
    element_pow_zn(temp, u, x);  // f_acc(u, x) = u^x
    element_invert(temp, temp);  // 对 f_acc(u, x) 取反
    element_mul(V, V, temp);     // 更新 V = V / f_acc(u, x)
    element_clear(temp);
}

// 获取当前累加器值 V
void Accumulator::get_accumulator_value(element_t &result) {
    element_set(result, V);
}

void Accumulator::set_accumulator_value(element_t &value) {
    element_set(V, value);
}

// 生成给定 x 的见证
void Accumulator::get_witness(element_t &x, element_t &witness) {
    element_t temp;
    element_init_G1(temp, pairing);
    element_pow_zn(temp, u, x);  // f_acc(u, x) = u^x
    element_invert(temp, temp);  // 对 f_acc(u, x) 取反
    element_mul(witness, V, temp); // w_i = f_acc(u, {x_1,..., x_n} \ {x_i})
    element_clear(temp);
}

// 清理资源
Accumulator::~Accumulator() {
    element_clear(u);
    element_clear(V);
    pairing_clear(pairing);
}