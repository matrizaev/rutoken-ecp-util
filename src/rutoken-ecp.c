#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdbool.h>

#include <rutoken/rtpkcs11.h>

#include "rutoken-ecp.h"
#include "errors.h"
#include "dbg.h"

typedef struct
{
    void *pkcs11Handle;

    CK_SLOT_ID_PTR slots;
    CK_ULONG slotCount;
    size_t slot;
    CK_FUNCTION_LIST_PTR functionList;
    CK_FUNCTION_LIST_EXTENDED_PTR functionListEx;
    CK_SESSION_HANDLE session;
} RutokenEcpContext;

static void close_pkcs11(RutokenEcpContext context)
{

    CK_RV rv = 0;
    /*************************************************************************
     * Close open session                                                    *
     *************************************************************************/
    if (context.session != 0)
    {
        rv = context.functionList->C_Logout(context.session);
        if (rv != CKR_OK)
            log_err("%s", rv_to_str(rv));
        rv = context.functionList->C_CloseSession(context.session);
        if (rv != CKR_OK)
            log_err("%s", rv_to_str(rv));
    }

    /*************************************************************************
     * Free the slots array                                                  *
     *************************************************************************/
    if (context.slots != NULL)
    {
        free(context.slots);
    }

    /*************************************************************************
     * Finalize the PKCS#11 library                                          *
     *************************************************************************/
    if (context.functionList != NULL)
    {
        rv = context.functionList->C_Finalize(NULL);
        if (rv != CKR_OK)
            log_err("%s", rv_to_str(rv));
    }

    /*************************************************************************
     * Unload the shared library                                             *
     *************************************************************************/
    if (context.pkcs11Handle != NULL)
    {
        dlclose(context.pkcs11Handle);
    }
    return;
}

static RutokenEcpContext init_pkcs11(uint8_t *userPIN, size_t userPINLen, size_t slot)
{
    RutokenEcpContext result = {0};
    bool success = false;

    CK_RV rv = 0;

    CK_C_GetFunctionList getFunctionList = NULL;
    CK_C_EX_GetFunctionListExtended getFunctionListEx = NULL;

    check(userPIN != NULL && userPINLen, "Function input is invalid.");

    /*************************************************************************
     * Load the shared library                                               *
     *************************************************************************/

    result.pkcs11Handle = dlopen(PKCS11_LIBRARY_NAME, RTLD_NOW);
    check(result.pkcs11Handle != NULL, "%s", dlerror());

    /*************************************************************************
     * Get the address of the C_GetFunctionList function                     *
     *************************************************************************/

    getFunctionList = (CK_C_GetFunctionList)dlsym(result.pkcs11Handle, "C_GetFunctionList");
    check(getFunctionList != NULL, "C_GetFunctionList: %s", dlerror());

    /*************************************************************************
     * Get the address of the C_EX_GetFunctionListExtended function          *
     *************************************************************************/

    getFunctionListEx = (CK_C_EX_GetFunctionListExtended)dlsym(result.pkcs11Handle, "C_EX_GetFunctionListExtended");
    check(getFunctionListEx != NULL, "C_EX_GetFunctionListExtended: %s", dlerror());

    /*************************************************************************
     * Get the function list                                                 *
     *************************************************************************/

    rv = getFunctionList(&result.functionList);
    check(rv == CKR_OK, "getFunctionList: %s", rv_to_str(rv));

    /*************************************************************************
     * Get the extended function list                                        *
     *************************************************************************/

    rv = getFunctionListEx(&result.functionListEx);
    check(rv == CKR_OK, "getFunctionListEx: %s", rv_to_str(rv));

    /*************************************************************************
     * Initialize the PKCS#11 library                                        *
     *************************************************************************/

    rv = result.functionList->C_Initialize(NULL);
    check(rv == CKR_OK, "C_Initialize: %s", rv_to_str(rv));

    /*************************************************************************
     * Get the number of available slots                                     *
     *************************************************************************/

    rv = result.functionList->C_GetSlotList(CK_TRUE, NULL, &result.slotCount);
    check((rv == CKR_OK) && (result.slotCount != 0) && (slot <= result.slotCount - 1), "There are no slots available: %s", rv_to_str(rv));

    /*************************************************************************
     * List the available slots                                              *
     *************************************************************************/

    result.slots = (CK_SLOT_ID_PTR)malloc(result.slotCount * sizeof(CK_SLOT_ID));
    check_mem(result.slots);

    rv = result.functionList->C_GetSlotList(CK_TRUE, result.slots, &result.slotCount);
    check((rv == CKR_OK) && (result.slotCount != 0) && (slot <= result.slotCount - 1), "There are no slots available: %s", rv_to_str(rv));

    /*************************************************************************
     * Open an RW session to the slot                                        *
     *************************************************************************/

    rv = result.functionList->C_OpenSession(result.slots[slot], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &result.session);
    check(rv == CKR_OK, "C_OpenSession: %s", rv_to_str(rv));

    /*************************************************************************
     * Authenticate the user                                                 *
     *************************************************************************/

    rv = result.functionList->C_Login(result.session, CKU_USER, userPIN, userPINLen);
    check(rv == CKR_OK, "C_Login: %s", rv_to_str(rv));

    success = true;
error:
    if (!success)
    {
        close_pkcs11(result);
        memset(&result, 0, sizeof(result));
    }
    return result;
}

/*************************************************************************
 * Find  objects by template
 *************************************************************************/
static int find_token_objects(CK_FUNCTION_LIST_PTR functionList, // PKCS#11 function list
                              CK_SESSION_HANDLE session,         // Open session handle
                              CK_ATTRIBUTE_PTR attributes,       // Template to use for searching
                              CK_ULONG attrCount,                // The size of the attribute array
                              CK_OBJECT_HANDLE_PTR *objects,     // The objects found
                              CK_ULONG *objectsCount             // The number of objects found
)
{
    CK_RV rv;                           // Return code
    CK_ULONG newObjectsCount;           // The number of objects found in the current call
    CK_ULONG bufferSize;                // The number of objects in the buffer
    CK_OBJECT_HANDLE_PTR buffer = NULL; // Memory to store objects
    int errorCode = 1;                  // Error flag

    /*************************************************************************
     * Initialize the search operation                                       *
     *************************************************************************/
    rv = functionList->C_FindObjectsInit(session, attributes, attrCount);
    check(rv == CKR_OK, "%s", rv_to_str(rv));
    errorCode = 2;

    /*************************************************************************
     * Find objects                                                          *
     *************************************************************************/
    *objects = NULL;
    *objectsCount = 0;

    for (bufferSize = 8;; bufferSize *= 2)
    {
        buffer = (CK_OBJECT_HANDLE_PTR)realloc(*objects, bufferSize * sizeof(CK_OBJECT_HANDLE));
        check_mem(buffer);
        *objects = buffer;

        rv = functionList->C_FindObjects(session, *objects + *objectsCount, bufferSize - *objectsCount, &newObjectsCount);
        check(rv == CKR_OK, "%s", rv_to_str(rv));

        *objectsCount += newObjectsCount;

        if (*objectsCount < bufferSize)
        {
            break;
        }
    }
    errorCode = 3;
    /*************************************************************************
     * Free the unused memory                                                *
     *************************************************************************/
    if (*objectsCount != 0)
    {
        buffer = (CK_OBJECT_HANDLE_PTR)realloc(*objects, *objectsCount * sizeof(CK_OBJECT_HANDLE));
        check_mem(buffer);
        *objects = buffer;
    }
    errorCode = 4;
error:
    /*************************************************************************
     * Finish the search operation                                           *
     *************************************************************************/
    if (errorCode > 1)
    {
        rv = functionList->C_FindObjectsFinal(session);
        if (rv != CKR_OK)
            log_err("%s", rv_to_str(rv));
        if (errorCode == 4)
            errorCode = 0;
    }
    /*************************************************************************
     * There was an error, free the memory and return an error code          *
     *************************************************************************/
    if (errorCode != 0 || *objectsCount == 0)
    {
        if (*objects != NULL)
        {
            free(*objects);
            *objects = NULL;
        }
    }
    return errorCode;
}

static bool pkcs11_initialized(RutokenEcpContext context)
{
    return context.pkcs11Handle != NULL &&
           context.functionList != NULL &&
           context.functionListEx != NULL &&
           context.slots != NULL &&
           context.session > 0;
}

void list_token(uint8_t *userPIN, size_t userPINLen, uint8_t *keyPairId, size_t keyPairIdLen, size_t slot)
{

    RutokenEcpContext context = init_pkcs11(userPIN, userPINLen, slot);

    check(pkcs11_initialized(context), "pkcs11 is not initialized");

    CK_RV rv;
    CK_INFO info = {0};
    CK_SLOT_INFO slotInfo = {0};
    CK_TOKEN_INFO tokenInfo = {0};

    rv = context.functionList->C_GetInfo(&info);
    check(rv == CKR_OK, "C_GetInfo: %s", rv_to_str(rv));

    printf("Cryptoki Version: %d.%d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
    printf("Manufacturer ID: %.32s\n", info.manufacturerID);
    printf("Library Description: %.32s\n", info.libraryDescription);
    printf("Library Version: %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);

    rv = C_GetSlotInfo(context.slots[context.slot], &slotInfo);
    check(rv == CKR_OK, "C_GetSlotInfo: %s", rv_to_str(rv));

    printf("Slot Description: %.64s\n", slotInfo.slotDescription);
    printf("Manufacturer ID: %.32s\n", slotInfo.manufacturerID);
    printf("Slot ID: %lu\n", context.slots[context.slot]);
    printf("Slot Flags: %lu\n", slotInfo.flags);
    printf("Hardware Version: %lu.%lu\n", slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor);
    printf("Firmware Version: %lu.%lu\n", slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor);

    rv = C_GetTokenInfo(context.slots[context.slot], &tokenInfo);
    check(rv == CKR_OK, "C_GetTokenInfo: %s", rv_to_str(rv));

    printf("Token Label: %.32s\n", tokenInfo.label);
    printf("Manufacturer ID: %.32s\n", tokenInfo.manufacturerID);
    printf("Token Model: %.32s\n", tokenInfo.model);
    printf("Token Serial Number: %.32s\n", tokenInfo.serialNumber);
    printf("Token Flags: %lu\n", tokenInfo.flags);
    printf("Session Count: %lu\n", tokenInfo.ulSessionCount);
    printf("Max Session Count: %lu\n", tokenInfo.ulMaxSessionCount);
    printf("Max R/W Session Count: %lu\n", tokenInfo.ulRwSessionCount);
    printf("Max Pin Length: %lu\n", tokenInfo.ulMaxPinLen);
    printf("Min Pin Length: %lu\n", tokenInfo.ulMinPinLen);
    printf("Total Public Memory: %lu\n", tokenInfo.ulTotalPublicMemory);
    printf("Free Public Memory: %lu\n", tokenInfo.ulFreePublicMemory);
    printf("Total Private Memory: %lu\n", tokenInfo.ulTotalPrivateMemory);
    printf("Free Private Memory: %lu\n", tokenInfo.ulFreePrivateMemory);
    printf("Hardware Version: %lu.%lu\n", tokenInfo.hardwareVersion.major, tokenInfo.hardwareVersion.minor);
    printf("Firmware Version: %lu.%lu\n", tokenInfo.firmwareVersion.major, tokenInfo.firmwareVersion.minor);

    // /*************************************************************************
    //  * Найти закрытый ключ на токене                                          *
    //  *************************************************************************/
    // int r = find_token_objects(functionList, session, privateKeyTemplate, arraysize(privateKeyTemplate),
    //                            &privateKeys, &keysCount);
    // check((r == 0) && (keysCount > 0), "There are no private keys available.");

    // /*************************************************************************
    //  * Найти сертификат на токене                                             *
    //  *************************************************************************/
    // r = find_token_objects(functionList, session, certificateTemplate, arraysize(certificateTemplate),
    //                        &certificates, &certificatesCount);
    // check(r == 0 && certificatesCount > 0, "There are no certificates available.");

error:
    /*************************************************************************
     * Освободить память, выделенную на объекты                               *
     *************************************************************************/
    // if (certificates != NULL)
    // {
    //     free(certificates);
    // }
    // if (privateKeys != NULL)
    // {
    //     free(privateKeys);
    // }

    close_pkcs11(context);
}

uint8_t *sign(void *inData, size_t inputLength, size_t *outputLength, uint8_t *userPIN, size_t userPINLen, uint8_t *keyPairId, size_t keyPairIdLen, size_t slot)
{
    /************************************************************************
     * Helper variables                                                     *
     ************************************************************************/
    CK_OBJECT_CLASS privateKeyObject = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS certificateObject = CKO_CERTIFICATE;
    CK_BBOOL attributeTrue = CK_TRUE;
    CK_CERTIFICATE_TYPE certificateType = CKC_X_509;

    CK_RV rv = 0;

    CK_OBJECT_HANDLE_PTR privateKeys = NULL;
    CK_ULONG keysCount = 0;

    CK_OBJECT_HANDLE_PTR certificates = NULL;
    CK_ULONG certificatesCount;

    CK_BYTE_PTR signature = NULL;
    CK_ULONG signatureSize = 0;
    uint8_t *result = NULL;

    check(inData != NULL && outputLength != NULL && userPIN != NULL && userPINLen && keyPairId != NULL && keyPairIdLen != 0, "Function input is invalid.");

    RutokenEcpContext context = init_pkcs11(userPIN, userPINLen, slot);
    check(pkcs11_initialized(context), "pkcs11 is not initialized");

    CK_ATTRIBUTE privateKeyTemplate[] =
        {
            {CKA_CLASS, &privateKeyObject, sizeof(privateKeyObject)}, // Object class is private key
            {CKA_TOKEN, &attributeTrue, sizeof(attributeTrue)},       // Token object
            {CKA_ID, keyPairId, keyPairIdLen},                        // Private key ID
        };

    CK_ATTRIBUTE certificateTemplate[] =
        {
            {CKA_CLASS, &certificateObject, sizeof(certificateObject)},        // Object class is certificate
            {CKA_TOKEN, &attributeTrue, sizeof(attributeTrue)},                // Token object
            {CKA_ID, keyPairId, keyPairIdLen},                                 // Certificate ID is the same as the private key ID
            {CKA_CERTIFICATE_TYPE, &certificateType, sizeof(certificateType)}, // An X.509 certificate
        };

    *outputLength = 0;

    /*************************************************************************
     * Find the private key on the token                                     *
     *************************************************************************/
    int r = find_token_objects(context.functionList, context.session, privateKeyTemplate, arraysize(privateKeyTemplate),
                               &privateKeys, &keysCount);
    check((r == 0) && (keysCount > 0), "There are no private keys available.");

    /*************************************************************************
     * Find the certificate on the token                                     *
     *************************************************************************/
    r = find_token_objects(context.functionList, context.session, certificateTemplate, arraysize(certificateTemplate),
                           &certificates, &certificatesCount);
    check(r == 0 && certificatesCount > 0, "There are no certificates available.");

    /*************************************************************************
     * Sign the data                                                         *
     *************************************************************************/
    rv = context.functionListEx->C_EX_PKCS7Sign(context.session, inData, inputLength, certificates[0],
                                                &signature, &signatureSize, privateKeys[0], NULL, 0, USE_HARDWARE_HASH | PKCS7_DETACHED_SIGNATURE);
    check(rv == CKR_OK && signatureSize != 0, "C_EX_PKCS7Sign: %s", rv_to_str(rv));

    /*************************************************************************
     * Copy the detached signature to the output buffer                      *
     *************************************************************************/
    result = malloc(signatureSize);
    check_mem(result);
    *outputLength = signatureSize;
    memcpy(result, signature, signatureSize);
error:
    /*************************************************************************
     * Free the memory                                                       *
     *************************************************************************/
    if (certificates != NULL)
    {
        free(certificates);
    }
    if (privateKeys != NULL)
    {
        free(privateKeys);
    }
    if (signature != NULL)
    {
        rv = context.functionListEx->C_EX_FreeBuffer(signature);
        if (rv != CKR_OK)
            log_err("C_EX_FreeBuffer: %s", rv_to_str(rv));
    }

    close_pkcs11(context);
    return result;
}
