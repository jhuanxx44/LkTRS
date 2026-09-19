#ifndef PP_H
#define PP_H

#include <gmp.h>
#include <pbc/pbc.h>
#include <string>
#include <utility>

struct PublicKey {
    element_t u_i;
    element_t y_i;
};

struct SecretKey {
    element_t x_i;
    element_t s_i;
    element_t t_i;
};



#endif