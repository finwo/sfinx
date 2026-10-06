sphincs+ inspired data signing library

Rough idea:

    4 bits of the original hash per tree layer
    original hash = tree path

    pre-image input = <N-seed><layer><masked-org-hash>
    pre-image source = shake256, get 32*32=1024 bytes

    each layer = cat( h(pre-image[i], current[i]) )
    pubkey of leaf = h(cat(h(pre-image[i], 256)))

    next layer = sign(cat(pubkeys of all leafs)) // 16 leafs per layer -- 4 bits

Pseudocode:

```c

char *seed    = "supersecret";
char *org     = h(message);
char *current = org;

char ** pre_img( char *seed, int mask, char *org_hash ) {
    char * pre_input  = concat( seed, mask/4, cidr(org_hash, mask) );
    char * pre_source = shake_init(pre_input);

    char *output[32];
    for(int i=0; i<32; i++) {
        output[i] = hash(pre_source.shake(32));
    }

    return output;
}

char ** sign( char **pre_image, char *current_hash ) {
    char *output[32];
    for(int n=0; n<32; n++) {
        output[i] = hash(pre_image[i], current_hash[i]);
    }
    return output;
}

char * pubkey_for( char **pre_image ) {
    char *output[32] = calloc(1, 32*32);
    memcpy(output, pre_image, 32*32);
    for(int n=0; n<32; n++) {
        for(int i=0; i<256; i++) {
            output[n] = hash(output[n]);
        }
    }
    return hash(concat(output));
}

// The full signing cycle
char *org     = hash(message);
char *current = org;
char *msg;

for ( int mask=256; mask>=0; mask-=4 ) {

    // Provide pre-image proof of current leaf
    char **pre   = pre_img( seed, mask, org );
    char **proof = sign(pre, current);
    append_preimage(out, proof);

    // Provide neighbours if not root
    if ( mask > 0 ) {
        int   self = bitbuffer_get_i4(current, mask-4);
        char *base = cidr(current, mask-4);

        msg = "";

        for(int i=0 ; i<16; i++) {
            bitbuffer_put_i4( org, mask-4, i);
            char *pub_neighbour = pubkey_for(pre_img( seed, mask, org ))
            append_pubkey(msg, pub_neighbour);
            if (i == self) continue;
            append_pubkey(out, pub_neighbour);
        }

        current = hash(msg);
    }

}
```

