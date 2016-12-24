#pragma once
static char b64_encode_table[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',  /* 0-7 */
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',  /* 8-15 */
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',  /* 16-23 */
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',  /* 24-31 */
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',  /* 32-39 */
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',  /* 40-47 */
    'w', 'x', 'y', 'z', '0', '1', '2', '3',  /* 48-55 */
    '4', '5', '6', '7', '8', '9', '+', '/'   /* 56-63 */
};
/* Do base-64 encoding on a hunk of bytes.   Return pointer to the
 ** bytes generated.  Base-64 encoding takes up 4/3 the space of the original,
 ** plus a bit for end-padding.  3/2+5 gives a safe margin.
 */
static char * b64_encode(unsigned const char* ptr, long len) {
    char * space;
    int ptr_idx;
    int c = 0;
    int d = 0;
    int space_idx = 0;
    int phase = 0;

    /*FIXME calculate the occupied space properly*/
    size_t size = ((size_t)len * 3) /2 + 5;
    space = malloc(size+1);
    space[size] = 0;

    for (ptr_idx = 0; ptr_idx < len; ++ptr_idx) {
        switch (phase++) {
            case 0:
                c = ptr[ptr_idx] >> 2;
                d = (ptr[ptr_idx] & 0x3) << 4;
                break;
            case 1:
                c = d | (ptr[ptr_idx] >> 4);
                d = (ptr[ptr_idx] & 0xf) << 2;
                break;
            case 2:
                c = d | (ptr[ptr_idx] >> 6);
                if (space_idx < size) space[space_idx++] = b64_encode_table[c];
                c = ptr[ptr_idx] & 0x3f;
                break;
        }
        space[space_idx++] = b64_encode_table[c];
        if (space_idx == size) return space;
        phase %= 3;
    }
    if (phase != 0) {
        space[space_idx++] = b64_encode_table[d];
        if (space_idx == size) return space;
        /* Pad with ='s. */
        while (phase++ > 0) {
            space[space_idx++] = '=';
            if (space_idx == size) return space;
            phase %= 3;
        }
    }
    return space;
}
