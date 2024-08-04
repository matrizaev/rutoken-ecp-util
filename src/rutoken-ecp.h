#include <stddef.h>
#include <stdint.h>

#define PKCS11_LIBRARY_NAME "librtpkcs11ecp.so"
#define arraysize(a) (sizeof(a) / sizeof(a[0]))

extern uint8_t *sign(void *inData, size_t inputLength, size_t *outputLength, uint8_t *userPIN, size_t userPINLen, uint8_t *keyPairId, size_t keyPairIdLen, size_t slot);
