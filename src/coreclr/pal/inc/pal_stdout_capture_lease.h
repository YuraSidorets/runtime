#ifndef PAL_STDOUT_CAPTURE_LEASE_H
#define PAL_STDOUT_CAPTURE_LEASE_H

#include "pal.h"

// Private CoreCLR/PAL coordination for the bounded process-fd-1 capture.
// The opaque object reference pins the exact PAL stdout file object; callers
// must release it after the borrowed descriptor is no longer used.
typedef struct _PAL_STDOUT_CAPTURE_LEASE
{
    void *object;
    int descriptor;
} PAL_STDOUT_CAPTURE_LEASE;

#ifdef __cplusplus
extern "C" {
#endif

PALIMPORT BOOL PALAPI PALAcquireStdoutCaptureLease(OUT PAL_STDOUT_CAPTURE_LEASE *lease);
PALIMPORT VOID PALAPI PALReleaseStdoutCaptureLease(IN OUT PAL_STDOUT_CAPTURE_LEASE *lease);

#ifdef __cplusplus
}
#endif

#endif // PAL_STDOUT_CAPTURE_LEASE_H
