#include "grad.h"
#include <stdint.h>
#include <iostream>

using namespace rgd;

Grad::Grad(size_t size) : grads(size) {
}

std::vector<GradUnit>& Grad::get_value() {
  return grads;
}


uint64_t Grad::max_val() {
  uint64_t ret = 0;
  for (auto &gradu : grads) { // by reference: avoid copying each GradUnit in this hot loop
    //std::cout << "graud value is " << gradu.val <<std::endl;
    if (gradu.val > ret)
      ret = gradu.val;
  }
  return ret;
}

void Grad::normalize() {
  double max_grad = (double)max_val();
  if (max_grad > 0.0) {
    for(auto &grad : grads) {
      grad.pct = 1.0 * ((double)grad.val / max_grad);
    }
  }
}

void Grad::clear() {
  for (auto &gradu : grads) { // by reference: iterating by value zeroed only copies
    gradu.val = 0;
    gradu.pct = 0.0;
  }
}

size_t Grad::len() {
  return grads.size();
}


uint64_t Grad::val_sum() {
  uint64_t ret = 0;
  for (auto &gradu : grads) {
    //FIXME: saturating_add
    // done: saturate on overflow so descend's guess_step (f0 / val_sum) stays sane
    uint64_t next = ret + gradu.val;
    ret = (next < ret) ? (uint64_t)-1 : next;
  }
  return ret;
}

