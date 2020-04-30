#include "utils.h"

// return the current value of a pairlist
SEXP pairlist_car(SEXP x) {
  if (!Rf_isList(x))
    Rf_error("x must be a pairlist");
  return CAR(x);
}

// return the next cons of a pairlist
SEXP pairlist_cdr(SEXP x) {
  if (!Rf_isList(x))
    Rf_error("x must be a pairlist");
  return CDR(x);
}

// return the last cons of a pairlist
SEXP pairlist_last(SEXP x) {
  if (!Rf_isList(x))
    Rf_error("x must be a pairlist");
  SEXP nx = CDR(x);
  while (!Rf_isNull(nx)) {
      x = nx;
      nx = CDR(x);
  }
  return x;
}


SEXP get_sexp_value(SEXP env, const char* name) {
    SEXP x = Rf_findVarInFrame(env, Rf_install(name));
    if (x == R_UnboundValue) {
        Rf_error("variable %s not found", name);
    }
    return x;
}


void set_sexp_value(SEXP env, const char* name, SEXP value) {
    PROTECT(value);
    Rf_defineVar(Rf_install(name), value, env);
    UNPROTECT(1);
}


int get_int_value(SEXP env, const char* name) {
    return Rf_asInteger(get_sexp_value(env, name));
}


void set_int_value(SEXP env, const char* name, int v) {
    SEXP v_ = PROTECT(Rf_ScalarInteger(v));
    Rf_defineVar(Rf_install(name), v_, env);
    UNPROTECT(1);
}


int add_int_value(SEXP env, const char* name, int v) {
    int x = get_int_value(env, name);
    x = x + v;
    SEXP x_ = PROTECT(Rf_ScalarInteger(x));
    Rf_defineVar(Rf_install(name), x_, env);
    UNPROTECT(1);
    return x;
}
