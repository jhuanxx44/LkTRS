#ifndef ACCUMULATOR_H
#define ACCUMULATOR_H

#include <gmp.h>
#include <pbc/pbc.h>
#include "pp.h"

class Accumulator {
public:
    Accumulator(const char* param_str);
    void set_generator(element_t &g);
    void add_user(element_t &x);
    void remove_user(element_t &x);
    void get_accumulator_value(element_t &result);
    void set_accumulator_value(element_t &value);
    void get_witness(element_t &x, element_t &witness);
    ~Accumulator();
protected:
    pairing_t pairing;
    element_t V;  // 当前累加器值 V
    element_t u;  // 累加器的生成元 u
};

#endif

