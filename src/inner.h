#ifndef AY_AES_INNER_H
#define AY_AES_INNER_H

#include <ay/aes.h>

#if defined(__GNUC__)
#define AY_TARGET(x) __attribute__((target(x)))
#else
#define AY_TARGET(x)
#endif /* defined (__GNUC__) */

#if defined(__GNUC__)
#define AY_FLATTEN __attribute__((flatten))
#else
#define AY_FLATTEN
#endif /* defined (__GNUC__) */

// Definition of struct aes_vtable is now private to the implementation
struct aes_vtable {
  void (*init)(AesContext *ctx, enum AesKeyType key_type,
               const unsigned char *key);

  void (*ctr_xcrypt)(AesContext *ctx, size_t textsize, unsigned char *out,
                     const unsigned char *in, unsigned char next_iv[16],
                     const unsigned char iv[16]);
  void (*ecb_encrypt)(AesContext *ctx, size_t textsize,
                      unsigned char *cipher_text,
                      const unsigned char *plain_text);
  void (*ecb_decrypt)(AesContext *ctx, size_t textsize,
                      unsigned char *plain_text,
                      const unsigned char *cipher_text);

  void (*cbc_encrypt)(AesContext *ctx, size_t textsize,
                      unsigned char *cipher_text,
                      const unsigned char *plain_text,
                      const unsigned char iv[16]);

  void (*cbc_decrypt)(AesContext *ctx, size_t textsize,
                      unsigned char *plain_text,
                      const unsigned char *cipher_text,
                      const unsigned char iv[16]);
};

#endif
