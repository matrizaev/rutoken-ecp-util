#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <rutoken/rtpkcs11.h>

#include "rutoken-ecp.h"
#include "errors.h"
#include "dbg.h"

/*************************************************************************
 * Функция поиска объектов по заданному шаблону                          *
 *************************************************************************/
static int findObjects(CK_FUNCTION_LIST_PTR functionList, // Указатель на список функций PKCS#11
                       CK_SESSION_HANDLE session,         // Хэндл открытой сессии
                       CK_ATTRIBUTE_PTR attributes,       // Массив с шаблоном для поиска
                       CK_ULONG attrCount,                // Количество атрибутов в массиве поиска
                       CK_OBJECT_HANDLE_PTR *objects,     // Массив для записи найденных объектов
                       CK_ULONG *objectsCount             // Количество найденных объектов
)
{
    CK_RV rv;                           // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11
    CK_ULONG newObjectsCount;           // Количество объектов, найденных при конкретном вызове C_FindObjects
    CK_ULONG bufferSize;                // Текущий размер буфера с объектами
    CK_OBJECT_HANDLE_PTR buffer = NULL; // Буфер, получаемый из realloc
    int errorCode = 1;                  // Флаг ошибки

    /*************************************************************************
     * Инициализировать операцию поиска                                       *
     *************************************************************************/
    rv = functionList->C_FindObjectsInit(session, attributes, attrCount);
    check(rv == CKR_OK, "%s", rv_to_str(rv));
    errorCode = 2;

    /*************************************************************************
     * Найти все объекты, соответствующие критериям поиска                    *
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
     * Освободить неиспользуемую память                                       *
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
     * Деинициализировать операцию поиска                                     *
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
     * Очистить память, выделенную под объекты                                *
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

uint8_t *sign(void *inData, size_t inputLength, size_t *outputLength, uint8_t *userPIN, size_t userPINLen, uint8_t *keyPairId, size_t keyPairIdLen, size_t slot)
{
    /************************************************************************
     * Вспомогательные переменные                                            *
     ************************************************************************/
    CK_OBJECT_CLASS privateKeyObject = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS certificateObject = CKO_CERTIFICATE;
    CK_BBOOL attributeTrue = CK_TRUE;
    CK_CERTIFICATE_TYPE certificateType = CKC_X_509;
    // CK_ULONG tokenUserCertificate = 1;

    void *pkcs11Handle = NULL;                                // Хэндл загруженной библиотеки PKCS#11
    CK_FUNCTION_LIST_PTR functionList = NULL;                 // Указатель на список функций PKCS#11, хранящийся в структуре CK_FUNCTION_LIST
    CK_C_GetFunctionList getFunctionList = NULL;              // Указатель на функцию C_GetFunctionList
    CK_FUNCTION_LIST_EXTENDED_PTR functionListEx = NULL;      // Указатель на список функций расширения PKCS#11, хранящийся в структуре CK_FUNCTION_LIST_EXTENDED
    CK_C_EX_GetFunctionListExtended getFunctionListEx = NULL; // Указатель на функцию C_EX_GetFunctionListExtended
    CK_SLOT_ID_PTR slots = NULL;                              // Указатель на массив идентификаторов слотов
    CK_ULONG slotCount = 0;                                   // Количество идентификаторов слотов в массиве
    CK_SESSION_HANDLE session = 0;                            // Хэндл открытой сессии
    CK_RV rv = 0;                                             // Код возврата. Могут быть возвращены только ошибки, определенные в PKCS#11

    CK_OBJECT_HANDLE_PTR privateKeys = NULL; // Указатель на массив хэндлов объектов, соответствующих критериям поиска закрытых ключей
    CK_ULONG keysCount = 0;                  // Количество найденных ключей

    CK_OBJECT_HANDLE_PTR certificates = NULL; // Указатель на массив хэндлов объектов, соответствующих критериям поиска сертификатов
    CK_ULONG certificatesCount;               // Количество найденных сертификатов

    CK_BYTE_PTR signature = NULL; // Указатель на буфер, содержащий подпись для исходных данных
    CK_ULONG signatureSize = 0;   // Размер буфера, содержащего подпись для исходных данных, в байтах
    uint8_t *result = NULL;

    check(inData != NULL && outputLength != NULL && userPIN != NULL && userPINLen && keyPairId != NULL && keyPairIdLen != 0, "Function input is invalid.");

    /*************************************************************************
     * Шаблон для поиска закрытого ключа ГОСТ Р 34.10-2012(256)               *
     *************************************************************************/
    CK_ATTRIBUTE privateKeyTemplate[] =
        {
            {CKA_CLASS, &privateKeyObject, sizeof(privateKeyObject)}, // Класс - закрытый ключ
            {CKA_TOKEN, &attributeTrue, sizeof(attributeTrue)},       // Закрытый ключ является объектом токена
            {CKA_ID, keyPairId, keyPairIdLen},                        // Идентификатор искомой пары
        };

    /*************************************************************************
     * Шаблон для поиска сертификата ключа проверки подписи                   *
     *************************************************************************/
    CK_ATTRIBUTE certificateTemplate[] =
        {
            {CKA_CLASS, &certificateObject, sizeof(certificateObject)},        // Класс - сертификат
            {CKA_TOKEN, &attributeTrue, sizeof(attributeTrue)},                // Сертификат является объектом токена
            {CKA_ID, keyPairId, keyPairIdLen},                                 // Идентификатор ключевой пары, которой соответствует сертификат
            {CKA_CERTIFICATE_TYPE, &certificateType, sizeof(certificateType)}, // Тип сертификата - X.509
                                                                               //		{ CKA_CERTIFICATE_CATEGORY, &tokenUserCertificate, sizeof(tokenUserCertificate)},	// Категория сертификата - пользовательский
        };

    *outputLength = 0;
    /*************************************************************************
     * Загрузить библиотеку                                                   *
     *************************************************************************/

    pkcs11Handle = dlopen(PKCS11_LIBRARY_NAME, RTLD_NOW);
    check(pkcs11Handle != NULL, "%s", dlerror());

    /*************************************************************************
     * Получить адрес функции запроса структуры с указателями на функции      *
     *************************************************************************/

    getFunctionList = (CK_C_GetFunctionList)dlsym(pkcs11Handle, "C_GetFunctionList");
    check(getFunctionList != NULL, "C_GetFunctionList: %s", dlerror());

    /*************************************************************************
     * Получить адрес функции запроса структуры с указателями на функции      *
     * расширения стандарта PKCS#11                                           *
     *************************************************************************/

    getFunctionListEx = (CK_C_EX_GetFunctionListExtended)dlsym(pkcs11Handle, "C_EX_GetFunctionListExtended");
    check(getFunctionListEx != NULL, "C_EX_GetFunctionListExtended: %s", dlerror());

    /*************************************************************************
     * Получить структуру с указателями на функции                            *
     *************************************************************************/

    rv = getFunctionList(&functionList);
    check(rv == CKR_OK, "getFunctionList: %s", rv_to_str(rv));

    /*************************************************************************
     * Получить структуру с указателями на функции расширения стандарта       *
     *************************************************************************/

    rv = getFunctionListEx(&functionListEx);
    check(rv == CKR_OK, "getFunctionListEx: %s", rv_to_str(rv));

    /*************************************************************************
     * Инициализировать библиотеку                                            *
     *************************************************************************/

    rv = functionList->C_Initialize(NULL);
    check(rv == CKR_OK, "C_Initialize: %s", rv_to_str(rv));

    /*************************************************************************
     * Получить количество слотов c подключенными токенами                    *
     *************************************************************************/

    rv = functionList->C_GetSlotList(CK_TRUE, NULL, &slotCount);
    check((rv == CKR_OK) && (slotCount != 0) && (slot <= slotCount - 1), "There are no slots available: %s", rv_to_str(rv));

    /*************************************************************************
     * Получить список слотов c подключенными токенами                        *
     *************************************************************************/

    slots = (CK_SLOT_ID_PTR)malloc(slotCount * sizeof(CK_SLOT_ID));
    check_mem(slots);

    rv = functionList->C_GetSlotList(CK_TRUE, slots, &slotCount);
    check((rv == CKR_OK) && (slotCount != 0) && (slot <= slotCount - 1), "There are no slots available: %s", rv_to_str(rv));

    /*************************************************************************
     * Открыть RW сессию в первом доступном слоте                             *
     *************************************************************************/

    rv = functionList->C_OpenSession(slots[slot], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    check(rv == CKR_OK, "C_OpenSession: %s", rv_to_str(rv));

    /*************************************************************************
     * Выполнить аутентификацию Пользователя                                  *
     *************************************************************************/

    rv = functionList->C_Login(session, CKU_USER, userPIN, userPINLen);
    check(rv == CKR_OK, "C_Login: %s", rv_to_str(rv));

    /*************************************************************************
     * Найти закрытый ключ на токене                                          *
     *************************************************************************/
    int r = findObjects(functionList, session, privateKeyTemplate, arraysize(privateKeyTemplate),
                        &privateKeys, &keysCount);
    check((r == 0) && (keysCount > 0), "There are no private keys available.");

    /*************************************************************************
     * Найти сертификат на токене                                             *
     *************************************************************************/
    r = findObjects(functionList, session, certificateTemplate, arraysize(certificateTemplate),
                    &certificates, &certificatesCount);
    check(r == 0 && certificatesCount > 0, "There are no certificates available.");

    /*************************************************************************
     * Подписать данные                                                       *
     *************************************************************************/
    rv = functionListEx->C_EX_PKCS7Sign(session, inData, inputLength, certificates[0],
                                        &signature, &signatureSize, privateKeys[0], NULL, 0, USE_HARDWARE_HASH | PKCS7_DETACHED_SIGNATURE);
    check(rv == CKR_OK && signatureSize != 0, "C_EX_PKCS7Sign: %s", rv_to_str(rv));

    /*************************************************************************
     * Копируем полученную PKCS7 CMS отсоединённую подпись.                   *
     *************************************************************************/
    result = malloc(signatureSize);
    check_mem(result);
    *outputLength = signatureSize;
    memcpy(result, signature, signatureSize);
error:
    /*************************************************************************
     * Освободить память, выделенную на объекты                               *
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
        rv = functionListEx->C_EX_FreeBuffer(signature);
        if (rv != CKR_OK)
            log_err("C_EX_FreeBuffer: %s", rv_to_str(rv));
    }

    /*************************************************************************
     * Закрыть открытую сессию в слоте                                        *
     *************************************************************************/
    if (session != 0)
    {
        rv = functionList->C_Logout(session);
        if (rv != CKR_OK)
            log_err("%s", rv_to_str(rv));
        rv = functionList->C_CloseSession(session);
        if (rv != CKR_OK)
            log_err("%s", rv_to_str(rv));
    }

    /*************************************************************************
     * Очистить память из-под слотов                                          *
     *************************************************************************/
    if (slots != NULL)
    {
        free(slots);
    }

    /*************************************************************************
     * Деинициализировать библиотеку                                          *
     *************************************************************************/
    if (functionList != NULL)
    {
        rv = functionList->C_Finalize(NULL);
        if (rv != CKR_OK)
            log_err("%s", rv_to_str(rv));
    }

    /*************************************************************************
     * Выгрузить библиотеку из памяти                                         *
     *************************************************************************/
    if (pkcs11Handle != NULL)
    {
        dlclose(pkcs11Handle);
    }
    return result;
}
