#include "signData.h"

namespace kiscSigner {

DWORD GetLastErrorCSP(HCRYPTPROV hProv)
{
    DWORD lastError = 0;
    DWORD len = sizeof(DWORD);
    CPGetProvParam(hProv, PP_LAST_ERROR, (unsigned char *)&lastError, &len, 0);
    return lastError;
}

int signData(std::string *profile, std::string *dataToSign, unsigned char *sign)
{
    unsigned long size;
    DWORD len;
    unsigned char *data = reinterpret_cast<unsigned char*>(const_cast<char*>(dataToSign->c_str()));
    char *profilec = reinterpret_cast<char*>(const_cast<char*>(profile->c_str()));
    unsigned char cert[8192];
    DWORD slen;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    ObjectInfoStr_t p7i;
    DWORD plen;
    LoadTumarCSP(NULL);
    if (!CPAcquireContext(&hProv, profilec, 0, NULL))
    {
        printf("error open profile - %s [%x]\n", profilec, GetLastErrorCSP(0));
        //delete[] data;
        return 0;
    }
    if (!CPGetUserKey(hProv, AT_SIGNATURE, &hKey))
    {
        printf("error get user key %x\n", GetLastErrorCSP(hProv));
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }
    slen = 8192;
    if (!CPGetKeyParam(hProv, hKey, KP_CERTIFICATE, cert, &slen, 0))
    {
        printf("error get certificate %x\n", GetLastErrorCSP(hProv));
        CPDestroyKey(hProv, hKey);
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }
    if (!CPCreateHash(hProv, CALG_TGR3411, 0, 0, &hHash))
    {
        printf("error create hash %x\n", GetLastErrorCSP(hProv));
        CPDestroyKey(hProv, hKey);
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }
    if (!CPHashData(hProv, hHash, (BYTE *)data, size, 0))
    {
        printf("error hash data - %x\n", GetLastErrorCSP(hProv));
        CPDestroyKey(hProv, hKey);
        CPDestroyHash(hProv, hHash);
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }
    if (!CPSetHashParam(hProv, hHash, HP_PKCS7_CERTIFICATE, cert, 0))
    {
        printf("error set certificate - %x\n", GetLastErrorCSP(hProv));
        CPDestroyKey(hProv, hKey);
        CPDestroyHash(hProv, hHash);
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }
    len = 8192;
    if (!CPSignHash(hProv, hHash, AT_SIGNATURE, NULL, CRYPT_SIGN_PKCS7, sign, &len))
    {
        printf("error sign data - %x\n", GetLastErrorCSP(hProv));
        CPDestroyKey(hProv, hKey);
        CPDestroyHash(hProv, hHash);
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }
    CPDestroyKey(hProv, hKey);
    CPDestroyHash(hProv, hHash);
    CPReleaseContext(hProv, 0);
    //delete[] data;
    FreeTumarCSP();
    return 1;
}

int verify(std::string *profile, std::string *dataToSign, unsigned char *sign)
{
    unsigned char *data = reinterpret_cast<unsigned char*>(const_cast<char*>(dataToSign->c_str()));
    char *profilec = reinterpret_cast<char*>(const_cast<char*>(profile->c_str()));
    unsigned long size;
    DWORD len;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    ObjectInfoStr_t p7i;
    DWORD plen;
    plen = sizeof(p7i);
    p7i.object.pbData = sign;
    p7i.object.cbData = len < 8192 ? len : 8192;
    LoadTumarCSP(NULL);
    plen = sizeof(p7i);
    p7i.object.pbData = sign;
    p7i.object.cbData = len < 8192 ? len : 8192;
    
    char *cpaSecondArg = nullptr;
    if (!CPAcquireContext(&hProv, cpaSecondArg, CRYPT_VERIFYCONTEXT, NULL))
    {
        printf("error load cryptoprovider - [%x]\n", GetLastErrorCSP(0));
        //delete[] data;
        return 0;
    }

    if (!CPGetProvParam(hProv, PP_PKCS7_CONTENT_OID, (BYTE *)&p7i, &len, 0))
    {
        printf("error parse pkcs#7 %x\n", GetLastErrorCSP(hProv));
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }

    if (!CPCreateHash(hProv, CALG_TGR3411, 0, 0, &hHash))
    {
        printf("error create hash %x\n", GetLastErrorCSP(hProv));
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }
    if (!CPSetHashParam(hProv, hHash, HP_PKCS7_BODY, sign, 0))
    {
        printf("error set hash param - %x\n", GetLastErrorCSP(hProv));
        CPDestroyHash(hProv, hHash);
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }

    if (!CPHashData(hProv, hHash, (BYTE *)data, size, 0))
    {
        printf("error hash data - %x\n", GetLastErrorCSP(hProv));
        CPDestroyHash(hProv, hHash);
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }

    DWORD certCount;
    plen = sizeof(certCount);
    if (!CPGetHashParam(hProv, hHash, HP_PKCS7_CRT_COUNT, (BYTE *)&certCount, &plen, 0))
    {
        printf("error get certificate - %x\n", GetLastErrorCSP(hProv));
        CPDestroyHash(hProv, hHash);
        CPReleaseContext(hProv, 0);
        //delete[] data;
        return 0;
    }

    unsigned char Cert[8196];
    unsigned char SN2[128];
    unsigned char date_from[64];
    unsigned char date_to[64];
    unsigned char DN[512];
    DWORD dn_len;
    DWORD date_size;
    DWORD len2;

    int i = 0;
    if (certCount)
    {
        plen = sizeof(Cert);
        if (CPGetHashParam(hProv, hHash, HP_PKCS7_ENUM_CERT, Cert, &plen, CRYPT_FIRST))
        {
            do
            {
                if (CPImportKey(hProv, Cert, plen, 0, 0, &hKey))
                {
                    len2 = sizeof(SN2);
                    memset(SN2, 0, sizeof(SN2));
                    CPGetKeyParam(hProv, hKey, KP_KEY_SN, SN2, &len2, 0);

                    date_size = sizeof(date_from);
                    memset(date_from, 0, sizeof(date_from));
                    CPGetKeyParam(hProv, hKey, KP_CRT_VFROM, date_from, &date_size, 0);
                    printf("cert valid date from - %s\n", date_from);

                    date_size = sizeof(date_to);
                    memset(date_to, 0, sizeof(date_to));
                    CPGetKeyParam(hProv, hKey, KP_CRT_VTO, date_to, &date_size, 0);
                    printf("cert valid date to - %s\n", date_to);

                    if (!CPVerifySignature(hProv, hHash, sign, len, hKey, 0, 0))
                    {
                        printf("error verify signature - %x\n", GetLastErrorCSP(hProv));
                    }
                    else
                    {
                        printf("Signature verify\n");
                    }
                    CPDestroyKey(hProv, hKey);
                    hKey = 0;
                    i++;
                }
                len = sizeof(Cert);
            } while (CPGetHashParam(hProv, hHash, HP_PKCS7_ENUM_CERT, Cert, &len, 0));
        }
    }

    CPDestroyHash(hProv, hHash);
    CPReleaseContext(hProv, 0);
    //delete[] data;
    free(data);
    FreeTumarCSP();
    return 1;
}

};

