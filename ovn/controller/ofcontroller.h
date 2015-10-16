
#ifndef OFCONTROLLER_H
#define OFCONTROLLER_H 1

#include <stdint.h>

/* Interface for OVN main loop. */
void ofcontroller_init(char const*);
void ofcontroller_run(const struct ovsrec_bridge *br_int);
void ofcontroller_wait(void);
void ofcontroller_destroy(void);


#endif
