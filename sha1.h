#ifndef SHA1_H
#define SHA1_H

#ifndef u32
#define u32 unsigned int
#endif

void sha1hash(u32 *in, u32 fullblocks, u32 len, u32 *output);
void sha1hash_fixed(u32 *in, u32 fullblocks, u32 *output);

#endif //__SHA1_H
