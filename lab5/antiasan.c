
#include <stdint.h>
#include <string.h>
#include <stdio.h>

void antiasan(unsigned long addr) {
    const unsigned long kShadowOffset = 0x7fff8000;

    unsigned long shadow_start = (addr + 0x87 >> 3) + kShadowOffset;
    unsigned long shadow_end   = ((addr + 0x87 + 0x58) >> 3) + kShadowOffset;


    if (1) {
        *(char *)shadow_end = 0x00;
        shadow_end   = ((addr + 0x87 + 0x60) >> 3) + kShadowOffset;
        *(char *)shadow_end = 0x00;
        }


}
