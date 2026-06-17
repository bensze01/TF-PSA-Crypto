/* A simple bump allocator for mldsa-native, allocating from a global buffer */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "tf_psa_crypto_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED) && \
    defined(TF_PSA_CRYPTO_PQCP_BUFFER_ALLOC)

#include "wrap_mldsa_native.h"
#include "src/common.h"

static MLD_ALIGN uint8_t tf_psa_crypto_pqcp_alloc_buffer[TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE];
static size_t tf_psa_crypto_pqcp_alloc_used;
static int tf_psa_crypto_pqcp_alloc_status;

#if defined(MBEDTLS_TEST_HOOKS)
static int tf_psa_crypto_pqcp_alloc_poison_mode;
static size_t tf_psa_crypto_pqcp_alloc_poison_bytes;

enum poison_mode {
    POISON_NONE,
    POISON_ON_LOCK,
    POISON_ON_UNLOCK,
};

enum poison_size {
    POISON_ZERO,
    POISON_SIGNATURE_INTERNAL_MINUS_ONE,
    POISON_SIGNATURE_INTERNAL,
    POISON_KEYPAIR_INTERNAL_MINUS_ONE,
    POISON_KEYPAIR_INTERNAL,
    POISON_VERIFY_MINUS_ONE,
    POISON_VERIFY,
    POISON_ALL,
};

psa_status_t tf_psa_crypto_pqcp_alloc_poison_setup(int poison_mode, int poison_size)
{
    size_t poison_bytes = TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE;
    switch (poison_size) {
        case POISON_ZERO:
            poison_bytes = 0;
            break;
        case POISON_SIGNATURE_INTERNAL:
            poison_bytes += MLD_DEFAULT_ALIGN;
        /* fall through */
        case POISON_SIGNATURE_INTERNAL_MINUS_ONE:
            poison_bytes -= TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE_SIGNATURE_INTERNAL(87);
            break;
        case POISON_KEYPAIR_INTERNAL:
            poison_bytes += MLD_DEFAULT_ALIGN;
        /* fall through */
        case POISON_KEYPAIR_INTERNAL_MINUS_ONE:
            poison_bytes -= TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE_KEYPAIR(87);
            break;
        case POISON_VERIFY:
            poison_bytes += MLD_DEFAULT_ALIGN;
        /* fall through */
        case POISON_VERIFY_MINUS_ONE:
            poison_bytes -= TF_PSA_CRYPTO_PQCP_ALLOC_BUFFER_SIZE_VERIFY(87);
            break;
        case POISON_ALL:
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }

    tf_psa_crypto_pqcp_alloc_poison_mode = poison_mode;
    tf_psa_crypto_pqcp_alloc_poison_bytes = poison_bytes;

    switch(poison_mode) {
        case POISON_NONE:
            if (poison_size != POISON_ZERO) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case POISON_ON_LOCK:
            break;
        case POISON_ON_UNLOCK:
            tf_psa_crypto_pqcp_alloc_pop(poison_bytes);
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;
}

void tf_psa_crypto_pqcp_alloc_poison_cleanup(void)
{
    tf_psa_crypto_pqcp_alloc_used = 0;
    tf_psa_crypto_pqcp_alloc_status = PSA_SUCCESS;
    tf_psa_crypto_pqcp_alloc_poison_mode = POISON_NONE;
    tf_psa_crypto_pqcp_alloc_poison_bytes = 0;
}

void tf_psa_crypto_pqcp_alloc_start_poison(void)
{
    if (tf_psa_crypto_pqcp_alloc_poison_mode == POISON_ON_LOCK) {
        tf_psa_crypto_pqcp_alloc_push(tf_psa_crypto_pqcp_alloc_poison_bytes);
    } else if (tf_psa_crypto_pqcp_alloc_poison_mode == POISON_ON_UNLOCK) {
        tf_psa_crypto_pqcp_alloc_pop(tf_psa_crypto_pqcp_alloc_poison_bytes);
    }
}
#endif /* MBEDTLS_TEST_HOOKS */

psa_status_t tf_psa_crypto_pqcp_alloc_done(void)
{
#if defined(MBEDTLS_TEST_HOOKS)
    if (tf_psa_crypto_pqcp_alloc_poison_mode == POISON_ON_LOCK) {
        tf_psa_crypto_pqcp_alloc_pop(tf_psa_crypto_pqcp_alloc_poison_bytes);
    }
#endif
    psa_status_t status = tf_psa_crypto_pqcp_alloc_status;
    tf_psa_crypto_pqcp_alloc_status = 0;
    if (tf_psa_crypto_pqcp_alloc_used != 0) {
        status = PSA_ERROR_BAD_STATE;
        tf_psa_crypto_pqcp_alloc_used = 0;
    }
#if defined(MBEDTLS_TEST_HOOKS)
    if (tf_psa_crypto_pqcp_alloc_poison_mode == POISON_ON_UNLOCK) {
        tf_psa_crypto_pqcp_alloc_push(tf_psa_crypto_pqcp_alloc_poison_bytes);
    }
#endif
    TF_PSA_CRYPTO_PQCP_ALLOC_UNLOCK();
    return status;
}

/* The base address and every allocation are aligned to a multiple
 * of MLD_ALIGN. */
void *tf_psa_crypto_pqcp_alloc_push(size_t size)
{
    /* If something's already gone wrong, avoid doing anything that could
     * make things worse. */
    if (tf_psa_crypto_pqcp_alloc_status != PSA_SUCCESS) {
        return NULL;
    }

    /* Check that there is room. This shouldn't happen if the buffer size
     * was configured correctly. */
    if (tf_psa_crypto_pqcp_alloc_used + size > sizeof(tf_psa_crypto_pqcp_alloc_buffer)) {
        tf_psa_crypto_pqcp_alloc_status = PSA_ERROR_INSUFFICIENT_MEMORY;
        return NULL;
    }

    void *p = tf_psa_crypto_pqcp_alloc_buffer + tf_psa_crypto_pqcp_alloc_used;
    tf_psa_crypto_pqcp_alloc_used += size;
    return p;
}

/* The base address and every allocation are aligned to a multiple
 * of MLD_ALIGN. */
void tf_psa_crypto_pqcp_alloc_pop(size_t size)
{
    /* This shouldn't happen, but make sure we don't underflow the buffer. */
    if (tf_psa_crypto_pqcp_alloc_used < size) {
        tf_psa_crypto_pqcp_alloc_status = PSA_ERROR_BAD_STATE;
        return;
    }

    tf_psa_crypto_pqcp_alloc_used -= size;
}

#endif
