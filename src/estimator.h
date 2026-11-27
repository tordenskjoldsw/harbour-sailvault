#ifndef ESTIMATOR_H
#define ESTIMATOR_H

#ifdef __cplusplus
extern "C" {
#endif

/* The password strength estimator the core is given (SvEstimator): rates
 * zero-terminated text with zxcvbn-c and returns its entropy in bits. Plain
 * C, so a password the core lends it is read by no C++ or Qt code. Some
 * passwords take it seconds; never call it on the UI thread. */
double sv_estimate(const char *password);

#ifdef __cplusplus
}
#endif

#endif /* ESTIMATOR_H */
