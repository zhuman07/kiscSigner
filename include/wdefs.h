//----------------------------------------------------------------------------
//
//  Microsoft Windows
//  Copyright (C) Microsoft Corporation, 1992-1999.
//
//----------------------------------------------------------------------------
#ifndef  __WDEFS_H
#define  __WDEFS_H

#include "tdefs.h"

#define WINAPI

#define MAX_PATH 260
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE 
#define TRUE  1
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

typedef void           VOID;
typedef char           CHAR;
typedef unsigned char  UCHAR;
typedef int            BOOL;
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef ulong32        DWORD;
typedef ulong32        ALG_ID;
typedef void          *PVOID;
typedef void          *LPVOID;
typedef char          *LPSTR;
//typedef char          *LPCWSTR;
typedef wchar_t       *LPCWSTR;
typedef void          *HANDLE;
typedef void          *HWND;
typedef void          *HINSTANCE;
typedef HINSTANCE      HMODULE;
typedef int          (*FARPROC)();
#define ULONG_PTR    unsigned long
typedef ULONG_PTR      HCRYPTPROV;
typedef ULONG_PTR      HCRYPTKEY;
typedef ULONG_PTR      HCRYPTHASH;

#define CRYPT_IMPL_SOFTWARE     2
#define CUR_BLOB_VERSION        2

typedef struct _VTableProvStruc {
    DWORD   Version;
    FARPROC FuncVerifyImage;
    FARPROC FuncReturnhWnd;
    DWORD   dwProvType;
    BYTE	*pbContextInfo;
    DWORD	cbContextInfo;
    LPSTR   pszProvName;
} VTableProvStruc, *PVTableProvStruc;

typedef struct _PROV_ENUMALGS {
    ALG_ID    aiAlgid;
    DWORD     dwBitLen;
    DWORD     dwNameLen;
    CHAR      szName[20];
} PROV_ENUMALGS;

typedef struct _PROV_ENUMALGS_EX {
    ALG_ID    aiAlgid;
    DWORD     dwDefaultLen;
    DWORD     dwMinLen;
    DWORD     dwMaxLen;
    DWORD     dwProtocols;
    DWORD     dwNameLen;
    CHAR      szName[20];
    DWORD     dwLongNameLen;
    CHAR      szLongName[40];
} PROV_ENUMALGS_EX;

typedef struct _PUBLICKEYSTRUC {
        BYTE    bType;
        BYTE    bVersion;
        WORD    reserved;
        ALG_ID  aiKeyAlg;
} BLOBHEADER, PUBLICKEYSTRUC;

typedef struct _RSAPUBKEY {
        DWORD   magic;                  // Has to be RSA1
        DWORD   bitlen;                 // # of bits in modulus
        DWORD   pubexp;                 // public exponent
                                        // Modulus data follows
} RSAPUBKEY;

typedef struct _PUBKEY {
        DWORD   magic;
        DWORD   bitlen;                 // # of bits in modulus
} DHPUBKEY, DSSPUBKEY, KEAPUBKEY, TEKPUBKEY;

typedef struct _DSSSEED {
        DWORD   counter;
        BYTE    seed[20];
} DSSSEED;

typedef struct _HMAC_Info {  
  ALG_ID HashAlgid;
  BYTE *pbInnerString;
  DWORD cbInnerString;
  BYTE *pbOuterString;
  DWORD cbOuterString;
} HMAC_INFO,*PHMAC_INFO;

typedef struct _CRYPTOAPI_BLOB {
    DWORD   cbData;
    BYTE    *pbData;
} CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB,
CRYPT_UINT_BLOB, *PCRYPT_UINT_BLOB,
CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB,
CERT_NAME_BLOB, *PCERT_NAME_BLOB,
CERT_RDN_VALUE_BLOB, *PCERT_RDN_VALUE_BLOB,
CERT_BLOB, *PCERT_BLOB,
CRL_BLOB, *PCRL_BLOB,
DATA_BLOB, *PDATA_BLOB,
CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB,
CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB,
CRYPT_DIGEST_BLOB, *PCRYPT_DIGEST_BLOB,
CRYPT_DER_BLOB, *PCRYPT_DER_BLOB,
CRYPT_ATTR_BLOB, *PCRYPT_ATTR_BLOB;

// structure for use with CryptSetKeyParam with KP_SCHANNEL_ALG
typedef struct _SCHANNEL_ALG {
    DWORD   dwUse;
    ALG_ID  Algid;
    DWORD   cBits;
    DWORD   dwFlags;
    DWORD   dwReserved;
} SCHANNEL_ALG, *PSCHANNEL_ALG;

//HWND GetActiveWindow(VOID);

#define CRYPT_FLAG_PCT1    0x0001
#define CRYPT_FLAG_SSL2    0x0002
#define CRYPT_FLAG_SSL3    0x0004
#define CRYPT_FLAG_TLS1    0x0008
#define CRYPT_FLAG_IPSEC   0x0010
#define CRYPT_FLAG_SIGNING 0x0020

// exported key blob definitions
#define SIMPLEBLOB              0x1
#define PUBLICKEYBLOB           0x6
#define PRIVATEKEYBLOB          0x7
#define PLAINTEXTKEYBLOB        0x8
#define OPAQUEKEYBLOB           0x9
#define PUBLICKEYBLOBEX         0xA
#define SYMMETRICWRAPKEYBLOB    0xB

#define AT_KEYEXCHANGE          1
#define AT_SIGNATURE            2

#define PKCS5_PADDING           1       // PKCS 5 (sec 6.2) padding method

// dwFlag definitions for CryptGenKey
#define CRYPT_EXPORTABLE        0x00000001
#define CRYPT_USER_PROTECTED    0x00000002
#define CRYPT_CREATE_SALT       0x00000004
#define CRYPT_UPDATE_KEY        0x00000008
#define CRYPT_NO_SALT           0x00000010
#define CRYPT_PREGEN            0x00000040
#define CRYPT_RECIPIENT         0x00000010
#define CRYPT_INITIATOR         0x00000040
#define CRYPT_ONLINE            0x00000080
#define CRYPT_SF                0x00000100
#define CRYPT_CREATE_IV         0x00000200
#define CRYPT_KEK               0x00000400
#define CRYPT_DATA_KEY          0x00000800
#define CRYPT_VOLATILE          0x00001000
#define CRYPT_SGCKEY            0x00002000

#define SCHANNEL_MAC_KEY    0x00000000
#define SCHANNEL_ENC_KEY    0x00000001

// dwFlags definitions for CryptDeriveKey
#define CRYPT_SERVER            0x00000400

// dwFlags definitions for CryptHashSessionKey
#define CRYPT_LITTLE_ENDIAN     0x00000001

#define szOID_RSA_SHA1RSA       "1.2.840.113549.1.1.5"

//
// CryptGetProvParam
//
#define PP_ENUMALGS             1
#define PP_ENUMCONTAINERS       2
#define PP_IMPTYPE              3
#define PP_NAME                 4
#define PP_VERSION              5
#define PP_CONTAINER            6
#define PP_CHANGE_PASSWORD      7
#define PP_KEYSET_SEC_DESCR     8       // get/set security descriptor of keyset
#define PP_CERTCHAIN            9       // for retrieving certificates from tokens
#define PP_KEY_TYPE_SUBTYPE     10
#define PP_PROVTYPE             16
#define PP_KEYSTORAGE           17
#define PP_APPLI_CERT           18
#define PP_SYM_KEYSIZE          19
#define PP_SESSION_KEYSIZE      20
#define PP_UI_PROMPT            21
#define PP_ENUMALGS_EX          22
#define PP_ENUMMANDROOTS        25
#define PP_ENUMELECTROOTS       26
#define PP_KEYSET_TYPE          27
#define PP_ADMIN_PIN            31
#define PP_KEYEXCHANGE_PIN      32
#define PP_SIGNATURE_PIN        33
#define PP_SIG_KEYSIZE_INC      34
#define PP_KEYX_KEYSIZE_INC     35
#define PP_UNIQUE_CONTAINER     36
#define PP_SGC_INFO             37
#define PP_USE_HARDWARE_RNG     38
#define PP_KEYSPEC              39
#define PP_ENUMEX_SIGNING_PROT  40

// dwParam
#define KP_IV                   1       // Initialization vector
#define KP_SALT                 2       // Salt value
#define KP_PADDING              3       // Padding values
#define KP_MODE                 4       // Mode of the cipher
#define KP_MODE_BITS            5       // Number of bits to feedback
#define KP_PERMISSIONS          6       // Key permissions DWORD
#define KP_ALGID                7       // Key algorithm
#define KP_BLOCKLEN             8       // Block size of the cipher
#define KP_KEYLEN               9       // Length of key in bits
#define KP_SALT_EX              10      // Length of salt in bytes
#define KP_P                    11      // DSS/Diffie-Hellman P value
#define KP_G                    12      // DSS/Diffie-Hellman G value
#define KP_Q                    13      // DSS Q value
#define KP_X                    14      // Diffie-Hellman X value
#define KP_Y                    15      // Y value
#define KP_RA                   16      // Fortezza RA value
#define KP_RB                   17      // Fortezza RB value
#define KP_INFO                 18      // for putting information into an RSA envelope
#define KP_EFFECTIVE_KEYLEN     19      // setting and getting RC2 effective key length
#define KP_SCHANNEL_ALG	        20      // for setting the Secure Channel algorithms
#define KP_CLIENT_RANDOM		  21      // for setting the Secure Channel client random data
#define KP_SERVER_RANDOM		  22      // for setting the Secure Channel server random data
#define KP_RP					     23
#define KP_PRECOMP_MD5			  24
#define KP_PRECOMP_SHA			  25
#define KP_CERTIFICATE          26      // for setting Secure Channel certificate data (PCT1)
#define KP_CLEAR_KEY            27      // for setting Secure Channel clear key data (PCT1)
#define KP_PUB_EX_LEN           28
#define KP_PUB_EX_VAL           29
#define KP_KEYVAL               30
#define KP_ADMIN_PIN            31
#define KP_KEYEXCHANGE_PIN      32
#define KP_SIGNATURE_PIN        33
#define KP_PREHASH              34

#define KP_OAEP_PARAMS          36      // for setting OAEP params on RSA keys
#define KP_CMS_KEY_INFO         37
#define KP_CMS_DH_KEY_INFO      38
#define KP_PUB_PARAMS           39      // for setting public parameters
#define KP_VERIFY_PARAMS        40      // for verifying DSA and DH parameters
#define KP_HIGHEST_VERSION      41      // for TLS protocol version setting

// KP_PERMISSIONS
#define CRYPT_ENCRYPT           0x0001  // Allow encryption
#define CRYPT_DECRYPT           0x0002  // Allow decryption
#define CRYPT_EXPORT            0x0004  // Allow key to be exported
#define CRYPT_READ              0x0008  // Allow parameters to be read
#define CRYPT_WRITE             0x0010  // Allow parameters to be set
#define CRYPT_MAC               0x0020  // Allow MACs to be used with key
#define CRYPT_EXPORT_KEY        0x0040  // Allow key to be used for exporting keys
#define CRYPT_IMPORT_KEY        0x0080  // Allow key to be used for importing keys

#define HP_ALGID                0x0001  // Hash algorithm
#define HP_HASHVAL              0x0002  // Hash value
#define HP_HASHSIZE             0x0004  // Hash value size
#define HP_HMAC_INFO            0x0005  // information for creating an HMAC
#define HP_TLS1PRF_LABEL        0x0006  // label for TLS1 PRF
#define HP_TLS1PRF_SEED         0x0007  // seed for TLS1 PRF

#define CRYPT_FAILED            FALSE
#define CRYPT_SUCCEED           TRUE

#define CRYPT_FIRST             1
#define CRYPT_NEXT              2
#define CRYPT_SGC_ENUM          4

#define CRYPT_IMPL_HARDWARE     1
#define CRYPT_IMPL_SOFTWARE     2
#define CRYPT_IMPL_MIXED        3
#define CRYPT_IMPL_UNKNOWN      4
#define CRYPT_IMPL_REMOVABLE    8

// key storage flags
#define CRYPT_SEC_DESCR         0x00000001
#define CRYPT_PSTORE            0x00000002
#define CRYPT_UI_PROMPT         0x00000004

// SGC flags
#define CRYPT_SGC               0x0001
#define CRYPT_FASTSGC           0x0002

//
// CryptSetProvParam
//
#define PP_CLIENT_HWND          1
#define PP_CONTEXT_INFO         11
#define PP_KEYEXCHANGE_KEYSIZE  12
#define PP_SIGNATURE_KEYSIZE    13
#define PP_KEYEXCHANGE_ALG      14
#define PP_SIGNATURE_ALG        15
#define PP_DELETEKEY            24

// KP_MODE
#define CRYPT_MODE_CBC          1       // Cipher block chaining
#define CRYPT_MODE_ECB          2       // Electronic code book
#define CRYPT_MODE_OFB          3       // Output feedback mode
#define CRYPT_MODE_CFB          4       // Cipher feedback mode
#define CRYPT_MODE_CTS          5       // Ciphertext stealing mode

// dwFlags definitions for CryptAcquireContext
#define CRYPT_VERIFYCONTEXT     0xF0000000
#define CRYPT_NEWKEYSET         0x00000008
#define CRYPT_DELETEKEYSET      0x00000010
#define CRYPT_MACHINE_KEYSET    0x00000020
#define CRYPT_SILENT            0x00000040

// dwFlags definitions for CryptSignHash and CryptVerifySignature
#define CRYPT_NOHASHOID         0x00000001
#define CRYPT_TYPE2_FORMAT      0x00000002
#define CRYPT_X931_FORMAT       0x00000004

// Algorithm classes
#define ALG_CLASS_ANY                   (0)
#define ALG_CLASS_SIGNATURE             (1 << 13)
#define ALG_CLASS_MSG_ENCRYPT           (2 << 13)
#define ALG_CLASS_DATA_ENCRYPT          (3 << 13)
#define ALG_CLASS_HASH                  (4 << 13)
#define ALG_CLASS_KEY_EXCHANGE          (5 << 13)
#define ALG_CLASS_ALL                   (7 << 13)

// Algorithm types
#define ALG_TYPE_ANY                    (0)
#define ALG_TYPE_DSS                    (1 << 9)
#define ALG_TYPE_RSA                    (2 << 9)
#define ALG_TYPE_BLOCK                  (3 << 9)
#define ALG_TYPE_STREAM                 (4 << 9)
#define ALG_TYPE_DH                     (5 << 9)
#define ALG_TYPE_SECURECHANNEL          (6 << 9)

#define ALG_SID_RSA_ANY                 0
#define ALG_SID_RSA_PKCS                1

#define ALG_SID_DSS_ANY                 0
#define ALG_SID_DSS_PKCS                1

#define ALG_SID_DH_EPHEM                2

#define ALG_SID_MD4                     2
#define ALG_SID_MD5                     3
#define ALG_SID_SHA                     4
#define ALG_SID_SHA1                    4
#define ALG_SID_MAC                     5

#define ALG_SID_SSL3SHAMD5              8
#define ALG_SID_HMAC                    9

#define ALG_SID_DES                     1
#define ALG_SID_3DES                    3
#define ALG_SID_3DES_112                9

#define ALG_SID_RC2                     2
#define ALG_SID_RC4                     1
#define ALG_SID_RC5                     13

#define ALG_SID_AES_128                 14
#define ALG_SID_AES_192                 15
#define ALG_SID_AES_256                 16

#define ALG_SID_TLS1PRF                 10

#define ALG_SID_MD2                     1

// secure channel sub ids
#define ALG_SID_SSL3_MASTER             1
#define ALG_SID_SCHANNEL_MASTER_HASH    2
#define ALG_SID_SCHANNEL_MAC_KEY        3
#define ALG_SID_PCT1_MASTER             4
#define ALG_SID_SSL2_MASTER             5
#define ALG_SID_TLS1_MASTER             6
#define ALG_SID_SCHANNEL_ENC_KEY        7

#define CALG_SSL3_MASTER        (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SSL3_MASTER)
#define CALG_SCHANNEL_MASTER_HASH   (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_MASTER_HASH)
#define CALG_SCHANNEL_MAC_KEY   (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_MAC_KEY)
#define CALG_SCHANNEL_ENC_KEY   (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SCHANNEL_ENC_KEY)
#define CALG_PCT1_MASTER        (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_PCT1_MASTER)
#define CALG_SSL2_MASTER        (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_SSL2_MASTER)
#define CALG_TLS1_MASTER        (ALG_CLASS_MSG_ENCRYPT|ALG_TYPE_SECURECHANNEL|ALG_SID_TLS1_MASTER)
#define CALG_TLS1PRF            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF)

#define CALG_MAC                (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_MAC)

#define CALG_DES                (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_DES)
#define CALG_3DES_112           (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_3DES_112)
#define CALG_3DES               (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_3DES)

#define CALG_RC2                (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_RC2)
#define CALG_RC4                (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_STREAM|ALG_SID_RC4)
#define CALG_RC5                (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_RC5)

#define CALG_AES_128            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_128)
#define CALG_AES_192            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_192)
#define CALG_AES_256            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_AES_256)

#define CALG_MD2                (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2)

#define CALG_MD5				        (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5)
#define CALG_SHA				        (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA)
#define CALG_SHA1				        (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1)
#define CALG_DH_EPHEM		            (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH_EPHEM)
#define CALG_RSA_SIGN			        (ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY)
#define CALG_DSS_SIGN			        (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_DSS_ANY)
#define CALG_RSA_KEYX			        (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA|ALG_SID_RSA_ANY)

#define CALG_SSL3_SHAMD5               (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SSL3SHAMD5)
#define CALG_HMAC                       (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC)

// Following are the definitions of various algorithm object identifiers
// RSA
#define szOID_RSA               "1.2.840.113549"
#define szOID_PKCS              "1.2.840.113549.1"
#define szOID_RSA_HASH          "1.2.840.113549.2"
#define szOID_RSA_ENCRYPT       "1.2.840.113549.3"

#define szOID_PKCS_1            "1.2.840.113549.1.1"
#define szOID_PKCS_2            "1.2.840.113549.1.2"
#define szOID_PKCS_3            "1.2.840.113549.1.3"
#define szOID_PKCS_4            "1.2.840.113549.1.4"
#define szOID_PKCS_5            "1.2.840.113549.1.5"
#define szOID_PKCS_6            "1.2.840.113549.1.6"
#define szOID_PKCS_7            "1.2.840.113549.1.7"
#define szOID_PKCS_8            "1.2.840.113549.1.8"
#define szOID_PKCS_9            "1.2.840.113549.1.9"
#define szOID_PKCS_10           "1.2.840.113549.1.10"

#define szOID_RSA_RSA           "1.2.840.113549.1.1.1"
#define szOID_RSA_MD2RSA        "1.2.840.113549.1.1.2"
#define szOID_RSA_MD4RSA        "1.2.840.113549.1.1.3"
#define szOID_RSA_MD5RSA        "1.2.840.113549.1.1.4"
#define szOID_RSA_SHA1RSA       "1.2.840.113549.1.1.5"
#define szOID_RSA_SETOAEP_RSA   "1.2.840.113549.1.1.6"
#define szOID_RSA_SHA256RSA     "1.2.840.113549.1.1.11" // sha256WithRSAEncryption 
#define szOID_RSA_SHA384RSA     "1.2.840.113549.1.1.12"
#define szOID_RSA_SHA512RSA     "1.2.840.113549.1.1.13"

#define szOID_RSA_data          "1.2.840.113549.1.7.1"
#define szOID_RSA_signedData    "1.2.840.113549.1.7.2"
#define szOID_RSA_envelopedData "1.2.840.113549.1.7.3"
#define szOID_RSA_signEnvData   "1.2.840.113549.1.7.4"
#define szOID_RSA_digestedData  "1.2.840.113549.1.7.5"
#define szOID_RSA_hashedData    "1.2.840.113549.1.7.5"
#define szOID_RSA_encryptedData "1.2.840.113549.1.7.6"

#define szOID_RSA_emailAddr     "1.2.840.113549.1.9.1"
#define szOID_RSA_unstructName  "1.2.840.113549.1.9.2"
#define szOID_RSA_contentType   "1.2.840.113549.1.9.3"
#define szOID_RSA_messageDigest "1.2.840.113549.1.9.4"
#define szOID_RSA_signingTime   "1.2.840.113549.1.9.5"
#define szOID_RSA_counterSign   "1.2.840.113549.1.9.6"
#define szOID_RSA_challengePwd  "1.2.840.113549.1.9.7"
#define szOID_RSA_unstructAddr  "1.2.840.113549.1.9.8"
#define szOID_RSA_extCertAttrs  "1.2.840.113549.1.9.9"
#define szOID_RSA_SMIMECapabilities "1.2.840.113549.1.9.15"
#define szOID_RSA_preferSignedData "1.2.840.113549.1.9.15.1"

#define szOID_RSA_MD2           "1.2.840.113549.2.2"
#define szOID_RSA_MD4           "1.2.840.113549.2.4"
#define szOID_RSA_MD5           "1.2.840.113549.2.5"

#define szOID_RSA_RC2CBC        "1.2.840.113549.3.2"
#define szOID_RSA_RC4           "1.2.840.113549.3.4"
#define szOID_RSA_DES_EDE3_CBC  "1.2.840.113549.3.7"
#define szOID_RSA_RC5_CBCPad    "1.2.840.113549.3.9"
#define szOID_X957_SHA1DSA      "1.2.840.10040.4.3"

// ITU-T UsefulDefinitions
#define szOID_DS                "2.5"
#define szOID_DSALG             "2.5.8"
#define szOID_DSALG_CRPT        "2.5.8.1"
#define szOID_DSALG_HASH        "2.5.8.2"
#define szOID_DSALG_SIGN        "2.5.8.3"
#define szOID_DSALG_RSA         "2.5.8.1.1"
// NIST OSE Implementors' Workshop (OIW)
// http://nemo.ncsl.nist.gov/oiw/agreements/stable/OSI/12s_9506.w51
// http://nemo.ncsl.nist.gov/oiw/agreements/working/OSI/12w_9503.w51
#define szOID_OIW               "1.3.14"
// NIST OSE Implementors' Workshop (OIW) Security SIG algorithm identifiers
#define szOID_OIWSEC            "1.3.14.3.2"
#define szOID_OIWSEC_md4RSA     "1.3.14.3.2.2"
#define szOID_OIWSEC_md5RSA     "1.3.14.3.2.3"
#define szOID_OIWSEC_md4RSA2    "1.3.14.3.2.4"
#define szOID_OIWSEC_desECB     "1.3.14.3.2.6"
#define szOID_OIWSEC_desCBC     "1.3.14.3.2.7"
#define szOID_OIWSEC_desOFB     "1.3.14.3.2.8"
#define szOID_OIWSEC_desCFB     "1.3.14.3.2.9"
#define szOID_OIWSEC_desMAC     "1.3.14.3.2.10"
#define szOID_OIWSEC_rsaSign    "1.3.14.3.2.11"
#define szOID_OIWSEC_dsa        "1.3.14.3.2.12"
#define szOID_OIWSEC_shaDSA     "1.3.14.3.2.13"
#define szOID_OIWSEC_mdc2RSA    "1.3.14.3.2.14"
#define szOID_OIWSEC_shaRSA     "1.3.14.3.2.15"
#define szOID_OIWSEC_dhCommMod  "1.3.14.3.2.16"
#define szOID_OIWSEC_desEDE     "1.3.14.3.2.17"
#define szOID_OIWSEC_sha        "1.3.14.3.2.18"
#define szOID_OIWSEC_mdc2       "1.3.14.3.2.19"
#define szOID_OIWSEC_dsaComm    "1.3.14.3.2.20"
#define szOID_OIWSEC_dsaCommSHA "1.3.14.3.2.21"
#define szOID_OIWSEC_rsaXchg    "1.3.14.3.2.22"
#define szOID_OIWSEC_keyHashSeal "1.3.14.3.2.23"
#define szOID_OIWSEC_md2RSASign "1.3.14.3.2.24"
#define szOID_OIWSEC_md5RSASign "1.3.14.3.2.25"
#define szOID_OIWSEC_sha1       "1.3.14.3.2.26"
#define szOID_OIWSEC_dsaSHA1    "1.3.14.3.2.27"
#define szOID_OIWSEC_dsaCommSHA1 "1.3.14.3.2.28"
#define szOID_OIWSEC_sha1RSASign "1.3.14.3.2.29"
// NIST OSE Implementors' Workshop (OIW) Directory SIG algorithm identifiers
#define szOID_OIWDIR            "1.3.14.7.2"
#define szOID_OIWDIR_CRPT       "1.3.14.7.2.1"
#define szOID_OIWDIR_HASH       "1.3.14.7.2.2"
#define szOID_OIWDIR_SIGN       "1.3.14.7.2.3"
#define szOID_OIWDIR_md2        "1.3.14.7.2.2.1"
#define szOID_OIWDIR_md2RSA     "1.3.14.7.2.3.1"
#define szOID_RSA_RSA           "1.2.840.113549.1.1.1"


// INFOSEC Algorithms
// joint-iso-ccitt(2) country(16) us(840) organization(1) us-government(101) dod(2) id-infosec(1)
#define szOID_INFOSEC                       "2.16.840.1.101.2.1"
#define szOID_INFOSEC_sdnsSignature         "2.16.840.1.101.2.1.1.1"
#define szOID_INFOSEC_mosaicSignature       "2.16.840.1.101.2.1.1.2"
#define szOID_INFOSEC_sdnsConfidentiality   "2.16.840.1.101.2.1.1.3"
#define szOID_INFOSEC_mosaicConfidentiality "2.16.840.1.101.2.1.1.4"
#define szOID_INFOSEC_sdnsIntegrity         "2.16.840.1.101.2.1.1.5"
#define szOID_INFOSEC_mosaicIntegrity       "2.16.840.1.101.2.1.1.6"
#define szOID_INFOSEC_sdnsTokenProtection   "2.16.840.1.101.2.1.1.7"
#define szOID_INFOSEC_mosaicTokenProtection "2.16.840.1.101.2.1.1.8"
#define szOID_INFOSEC_sdnsKeyManagement     "2.16.840.1.101.2.1.1.9"
#define szOID_INFOSEC_mosaicKeyManagement   "2.16.840.1.101.2.1.1.10"
#define szOID_INFOSEC_sdnsKMandSig          "2.16.840.1.101.2.1.1.11"
#define szOID_INFOSEC_mosaicKMandSig        "2.16.840.1.101.2.1.1.12"
#define szOID_INFOSEC_SuiteASignature       "2.16.840.1.101.2.1.1.13"
#define szOID_INFOSEC_SuiteAConfidentiality "2.16.840.1.101.2.1.1.14"
#define szOID_INFOSEC_SuiteAIntegrity       "2.16.840.1.101.2.1.1.15"
#define szOID_INFOSEC_SuiteATokenProtection "2.16.840.1.101.2.1.1.16"
#define szOID_INFOSEC_SuiteAKeyManagement   "2.16.840.1.101.2.1.1.17"
#define szOID_INFOSEC_SuiteAKMandSig        "2.16.840.1.101.2.1.1.18"
#define szOID_INFOSEC_mosaicUpdatedSig      "2.16.840.1.101.2.1.1.19"
#define szOID_INFOSEC_mosaicKMandUpdSig     "2.16.840.1.101.2.1.1.20"
#define szOID_INFOSEC_mosaicUpdatedInteg    "2.16.840.1.101.2.1.1.21"


#define _HRESULT_TYPEDEF_(_sc) _sc

#define ERROR_SUCCESS                    0L

//
// MessageId: ERROR_WRITE_FAULT
//
// MessageText:
//
//  The system cannot write to the specified device.
//
#define ERROR_WRITE_FAULT                29L

//
// MessageId: ERROR_READ_FAULT
//
// MessageText:
//
//  The system cannot read from the specified device.
//
#define ERROR_READ_FAULT                 30L

//
// MessageId: ERROR_INVALID_PASSWORD
//
// MessageText:
//
//  The specified network password is not correct.
//
#define ERROR_INVALID_PASSWORD           86L

//
// MessageId: ERROR_INVALID_PARAMETER
//
// MessageText:
//
//  The parameter is incorrect.
//
#define ERROR_INVALID_PARAMETER          87L    // dderror

//
// MessageId: ERROR_KEY_DELETED
//
// MessageText:
//
//  Illegal operation attempted on a registry key that has been marked for deletion.
//
#define ERROR_KEY_DELETED                1018L

//
// MessageId: NTE_BAD_UID
//
// MessageText:
//
//  Bad UID.
//
#define NTE_BAD_UID                      _HRESULT_TYPEDEF_(0x80090001L)

//
// MessageId: NTE_BAD_HASH
//
// MessageText:
//
//  Bad Hash.
//
#define NTE_BAD_HASH                     _HRESULT_TYPEDEF_(0x80090002L)

//
// MessageId: NTE_BAD_KEY
//
// MessageText:
//
//  Bad Key.
//
#define NTE_BAD_KEY                      _HRESULT_TYPEDEF_(0x80090003L)

//
// MessageId: NTE_BAD_LEN
//
// MessageText:
//
//  Bad Length.
//
#define NTE_BAD_LEN                      _HRESULT_TYPEDEF_(0x80090004L)

//
// MessageId: NTE_BAD_DATA
//
// MessageText:
//
//  Bad Data.
//
#define NTE_BAD_DATA                     _HRESULT_TYPEDEF_(0x80090005L)

//
// MessageId: NTE_BAD_SIGNATURE
//
// MessageText:
//
//  Invalid Signature.
//
#define NTE_BAD_SIGNATURE                _HRESULT_TYPEDEF_(0x80090006L)

//
// MessageId: NTE_BAD_VER
//
// MessageText:
//
//  Bad Version of provider.
//
#define NTE_BAD_VER                      _HRESULT_TYPEDEF_(0x80090007L)

//
// MessageId: NTE_BAD_ALGID
//
// MessageText:
//
//  Invalid algorithm specified.
//
#define NTE_BAD_ALGID                    _HRESULT_TYPEDEF_(0x80090008L)

//
// MessageId: NTE_BAD_FLAGS
//
// MessageText:
//
//  Invalid flags specified.
//
#define NTE_BAD_FLAGS                    _HRESULT_TYPEDEF_(0x80090009L)

//
// MessageId: NTE_BAD_TYPE
//
// MessageText:
//
//  Invalid type specified.
//
#define NTE_BAD_TYPE                     _HRESULT_TYPEDEF_(0x8009000AL)

//
// MessageId: NTE_BAD_KEY_STATE
//
// MessageText:
//
//  Key not valid for use in specified state.
//
#define NTE_BAD_KEY_STATE                _HRESULT_TYPEDEF_(0x8009000BL)

//
// MessageId: NTE_BAD_HASH_STATE
//
// MessageText:
//
//  Hash not valid for use in specified state.
//
#define NTE_BAD_HASH_STATE               _HRESULT_TYPEDEF_(0x8009000CL)

//
// MessageId: NTE_NO_KEY
//
// MessageText:
//
//  Key does not exist.
//
#define NTE_NO_KEY                       _HRESULT_TYPEDEF_(0x8009000DL)

//
// MessageId: NTE_NO_MEMORY
//
// MessageText:
//
//  Insufficient memory available for the operation.
//
#define NTE_NO_MEMORY                    _HRESULT_TYPEDEF_(0x8009000EL)

//
// MessageId: NTE_EXISTS
//
// MessageText:
//
//  Object already exists.
//
#define NTE_EXISTS                       _HRESULT_TYPEDEF_(0x8009000FL)

//
// MessageId: NTE_PERM
//
// MessageText:
//
//  Access denied.
//
#define NTE_PERM                         _HRESULT_TYPEDEF_(0x80090010L)

//
// MessageId: NTE_NOT_FOUND
//
// MessageText:
//
//  Object was not found.
//
#define NTE_NOT_FOUND                    _HRESULT_TYPEDEF_(0x80090011L)

//
// MessageId: NTE_DOUBLE_ENCRYPT
//
// MessageText:
//
//  Data already encrypted.
//
#define NTE_DOUBLE_ENCRYPT               _HRESULT_TYPEDEF_(0x80090012L)

//
// MessageId: NTE_BAD_PROVIDER
//
// MessageText:
//
//  Invalid provider specified.
//
#define NTE_BAD_PROVIDER                 _HRESULT_TYPEDEF_(0x80090013L)

//
// MessageId: NTE_BAD_PROV_TYPE
//
// MessageText:
//
//  Invalid provider type specified.
//
#define NTE_BAD_PROV_TYPE                _HRESULT_TYPEDEF_(0x80090014L)

//
// MessageId: NTE_BAD_PUBLIC_KEY
//
// MessageText:
//
//  Provider's public key is invalid.
//
#define NTE_BAD_PUBLIC_KEY               _HRESULT_TYPEDEF_(0x80090015L)

//
// MessageId: NTE_BAD_KEYSET
//
// MessageText:
//
//  Keyset does not exist
//
#define NTE_BAD_KEYSET                   _HRESULT_TYPEDEF_(0x80090016L)

//
// MessageId: NTE_PROV_TYPE_NOT_DEF
//
// MessageText:
//
//  Provider type not defined.
//
#define NTE_PROV_TYPE_NOT_DEF            _HRESULT_TYPEDEF_(0x80090017L)

//
// MessageId: NTE_PROV_TYPE_ENTRY_BAD
//
// MessageText:
//
//  Provider type as registered is invalid.
//
#define NTE_PROV_TYPE_ENTRY_BAD          _HRESULT_TYPEDEF_(0x80090018L)

//
// MessageId: NTE_KEYSET_NOT_DEF
//
// MessageText:
//
//  The keyset is not defined.
//
#define NTE_KEYSET_NOT_DEF               _HRESULT_TYPEDEF_(0x80090019L)

//
// MessageId: NTE_KEYSET_ENTRY_BAD
//
// MessageText:
//
//  Keyset as registered is invalid.
//
#define NTE_KEYSET_ENTRY_BAD             _HRESULT_TYPEDEF_(0x8009001AL)

//
// MessageId: NTE_PROV_TYPE_NO_MATCH
//
// MessageText:
//
//  Provider type does not match registered value.
//
#define NTE_PROV_TYPE_NO_MATCH           _HRESULT_TYPEDEF_(0x8009001BL)

//
// MessageId: NTE_SIGNATURE_FILE_BAD
//
// MessageText:
//
//  The digital signature file is corrupt.
//
#define NTE_SIGNATURE_FILE_BAD           _HRESULT_TYPEDEF_(0x8009001CL)

//
// MessageId: NTE_PROVIDER_DLL_FAIL
//
// MessageText:
//
//  Provider DLL failed to initialize correctly.
//
#define NTE_PROVIDER_DLL_FAIL            _HRESULT_TYPEDEF_(0x8009001DL)

//
// MessageId: NTE_PROV_DLL_NOT_FOUND
//
// MessageText:
//
//  Provider DLL could not be found.
//
#define NTE_PROV_DLL_NOT_FOUND           _HRESULT_TYPEDEF_(0x8009001EL)

//
// MessageId: NTE_BAD_KEYSET_PARAM
//
// MessageText:
//
//  The Keyset parameter is invalid.
//
#define NTE_BAD_KEYSET_PARAM             _HRESULT_TYPEDEF_(0x8009001FL)

//
// MessageId: NTE_FAIL
//
// MessageText:
//
//  An internal error occurred.
//
#define NTE_FAIL                         _HRESULT_TYPEDEF_(0x80090020L)

//
// MessageId: NTE_SYS_ERR
//
// MessageText:
//
//  A base error occurred.
//
#define NTE_SYS_ERR                      _HRESULT_TYPEDEF_(0x80090021L)

//
// MessageId: NTE_SILENT_CONTEXT
//
// MessageText:
//
//  Provider could not perform the action since the context was acquired as silent.
//
#define NTE_SILENT_CONTEXT               _HRESULT_TYPEDEF_(0x80090022L)

//
// MessageId: NTE_TOKEN_KEYSET_STORAGE_FULL
//
// MessageText:
//
//  The security token does not have storage space available for an additional container.
//
#define NTE_TOKEN_KEYSET_STORAGE_FULL    _HRESULT_TYPEDEF_(0x80090023L)

//
// MessageId: NTE_TEMPORARY_PROFILE
//
// MessageText:
//
//  The profile for the user is a temporary profile.
//
#define NTE_TEMPORARY_PROFILE            _HRESULT_TYPEDEF_(0x80090024L)

//
// MessageId: NTE_FIXEDPARAMETER
//
// MessageText:
//
//  The key parameters could not be set because the CSP uses fixed parameters.
//
#define NTE_FIXEDPARAMETER               _HRESULT_TYPEDEF_(0x80090025L)

//
// MessageId: ERROR_MORE_DATA
//
// MessageText:
//
//  More data is available.
//
#define ERROR_MORE_DATA                  234L    // dderror

//
// MessageId: ERROR_NO_MORE_ITEMS
//
// MessageText:
//
//  No more data is available.
//
#define ERROR_NO_MORE_ITEMS              259L

//
// MessageId: CRYPT_E_HASH_VALUE
//
// MessageText:
//
//  The hash value is not correct.
//
#define CRYPT_E_HASH_VALUE               _HRESULT_TYPEDEF_(0x80091007L)

#endif
//
// MessageId: ERROR_INVALID_TIME
//
// MessageText:
//
//  The specified time is invalid.
//
#define ERROR_INVALID_TIME               1901L

