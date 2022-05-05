//------------------------------------------------------------------------------
// Tumar CSP
// Copyright (c) 2008 Scientific Lab. Gamma Technologies. All rights reserved.
//
// Definition of exported functions and constants for CSP
//------------------------------------------------------------------------------
#ifndef __CPTUMAR_H
#define __CPTUMAR_H

#include "tdefs.h"
#ifndef WIND32
#include "wdefs.h"
#else
#include <windows.h>
#include <wincrypt.h>
#endif

typedef struct _VTableProvStruc {
    DWORD   Version;
    FARPROC FuncVerifyImage;
    FARPROC FuncReturnhWnd;
    DWORD   dwProvType;
    BYTE        *pbContextInfo;
    DWORD       cbContextInfo;
    LPSTR   pszProvName;
} VTableProvStruc, *PVTableProvStruc;
//------------------------------------------------------------------------------
#define PROV_TUMAR_DH           25
#define PROV_TUMAR_RSA          1
#define GT_TUMAR_PROV           "Tumar CSP"
#define GT_RSA_PROV             "Tumar CSP RSA"
//------------------------------------------------------------------------------
#define CRYPT_MS_KEYSET         0x01000000                            // flag for CPAcquireContext (not supported from 10.08.2010)
#define CRYPT_NEWKEYSETEX      (CRYPT_NEWKEYSET|CRYPT_MS_KEYSET)      // flag for CPAcquireContext (not supported from 10.08.2010)
#define CRYPT_OLD_TUM_KEYSET    0x02000000                            // flag for CPAcquireContext
#define CRYPT_NEWKEYSET_OLD    (CRYPT_NEWKEYSET|CRYPT_OLD_TUM_KEYSET) // flag for CPAcquireContext
//------------------------------------------------------------------------------
#define CRYPT_X509_FORMAT       0x00000080 // flag for CPSignHash/CPVerifySignature
#define CRYPT_NO_MATH_CACHE     0x00100000 // flag for CPVerifySignature
#define CRYPT_ECDSA             0x00200000 // flag for CPSignHash/CPVerifySignature/CPExportKey(p10/p7)
#define CRYPT_SIGN_ASN1         0x00400000 // flag for CPSignHash
#define CRYPT_SIGN_PKCS7        0x00080000 // flag for CPSignHash
#define PKCS7_CRT_INCLUDE       0x00040000 // flag for CPSignHash
#define PKCS7_PEM_ENCODING      0x00020000 // flag for CPSignHash
#define PKCS7_BASE64_ENCODING   0x00010000 // flag for CPSignHash
//------------------------------------------------------------------------------
#define CRYPT_OBJECT_CRT        0x01000000 // flag for CPVerifySignature
#define CRYPT_OBJECT_CRL        0x02000000 // flag for CPVerifySignature
#define CRYPT_OBJECT_P10        0x04000000 // flag for CPVerifySignature
#define CRYPT_OBJECT_CMP        0x08000000 // flag for CPVerifySignature
#define CRYPT_OBJECT_REV        0x00800000 // flag for CPVerifySignature
#define CRYPT_OBJECT_OCSP       0x10000000 // flag for CPVerifySignature
#define CRYPT_OBJECT_TSP        0x20000000 // flag for CPVerifySignature
#define CRYPT_OBJECT_P7A        0x40000000 // flag for CPVerifySignature
//------------------------------------------------------------------------------
#define CRYPT_P12_STD_EXPORT    0x00200000 // flag for CPExportKey
#define CRYPT_P12_STD_EXPORT_S  0x00800000 // flag for CPExportKey
#define CRYPT_CPRO_EXPORT       0x00400000 // flag for CPExportKey
#define CRYPT_ECC_EXPORT        0x01000000 // flag for CPExportKey
#define CRYPT_DEFAULT_MODE      0x02000000 // flag for CPExportKey
#define CRYPT_CMP_NO_IMP_CONF   0x00100000 // flag for CPExportKey
#define CRYPT_USE_OCSP_LOCATOR  0x00010000 // flag for CPExportKey
#define CRYPT_OLD_P10_FORMAT    0x00020000 // flag for CPExportKey
//------------------------------------------------------------------------------
#define CRYPT_USE_HARDWARE      0x40000000 // flag for CPCreateHash
//------------------------------------------------------------------------------
#define CRYPT_PBM_PADDING       0x02000000 // flag for CPDeriveKey (Derive for Password Based Mac (id-PasswordBasedMac ::= {1 2 840 113533 7 66 13}))
//------------------------------------------------------------------------------
#define CRYPT_MODE_CNT          20 // add mode for CPGetKeyParam/CPSetKeyParam (KP_MODE)
#define CRYPT_MODE_IMT          21 // add mode for CPGetKeyParam/CPSetKeyParam (KP_MODE)
#define CRYPT_MODE_X919         22 // add mode for CPGetKeyParam/CPSetKeyParam (KP_MODE)
//------------------------------------------------------------------------------
#define PP_ENUM_RANDOMGEN       43
#define PP_ENUM_KEYSTORAGE      44
#define PP_ENUM_CNT_PRIV_KEYS   45
#define PP_CNT_URL              46
#define PP_CNT_KEYS_COUNT       47
#define PP_CNT_KEYS             48
#define PP_CNT_DEL_SN           49
#define PP_CNT_DEL_NEW          50
#define PP_ENUM_EXCH_KEY_ALG    51
#define PP_ENUM_SIGN_KEY_ALG    52
#define PP_CREATE_KEY_CACHE     53
#define PP_DESTROY_KEY_CACHE    54
#define PP_LAST_ERROR           55
#define PP_PROFILE              56
#define PP_ENUMPROFILES         57
#define PP_PRIORITY             58   // not supported
#define PP_CNT_ENTER            59
#define PP_KEYMIX               60
#define PP_PROFILES_COUNT       61
#define PP_CNT_ENTER_BY_SN      62 // Activating key by SN
#define PP_PKCS_TO_SN           63
#define PP_URL_TO_PROF          64
#define PP_PROF_TO_URL          65
#define PP_ENUM_LICENSES        66
#define PP_ADD_PROFILE          67
#define PP_DEL_PROFILE          68
#define PP_DEF_EXCH_KEY_ALG     69
#define PP_DEF_SIGN_KEY_ALG     70
#define PP_COPY_CONTAINER       71
#define PP_MOVE_CONTAINER       72
#define PP_ENUM_CNT_CA_CERTS    73 // Enum CA certificates as CNT_CERT struct
#define PP_PKCS7_CNT_CA_DATA    74 // Get CA certificates and CRLs in PKCS7 blob
#define PP_CERTIFICATE_DEL      75 // Delete CA certificate by SN
#define PP_CNT_BLOCK_BY_SN      76 // Blocking key by SN
#define PP_PKCS7_CONTENT_OID    77
#define PP_SYS_TIME             78
#define PP_KEYSTORAGE_TYPE      79
#define PP_ENUM_PROFILE_URL     80
#define PP_TOKEN_INFO           81
#if defined(ARM32) || defined(WINCE)
#define PP_LICENSE_FILE         82
#endif
//------------------------------------------------------------------------------
#define KEYSTORAGE_TYPE_STORE 0x01
#define KEYSTORAGE_TYPE_TOKEN 0x02
//------------------------------------------------------------------------------
#define KP_KEY_TIME             50
#define KP_KEY_OID              51
#define KP_KEY_SN               52
#define KP_EXCH_TIME            60 // not supported
#define KP_SIGN_TIME            61 // not supported
#define KP_EXCH_OID             62 // not supported
#define KP_SIGN_OID             63 // not supported
#define KP_CNT_BODY             64 // not supported
#define KP_CIPHEROID            65
#define KP_CERTIFICATE_DEL      66
#define KP_USER_KEY             67
#define KP_CERTIFICATE_CA       68
#define KP_CERTIFICATE_CHAIN    69
#define KP_CERTIFICATE_CRL      70
#define KP_MESHING              71 // RFC-4357 (2.3.2. CryptoPro Key Meshing)
#define KP_SUBJECT_NAME         72
#define KP_ALG_TYPE             73 // OBJECT_ALG_TYPE_DH / OBJECT_ALG_TYPE_EC / OBJECT_ALG_TYPE_RSA
//------------------------------------------------------------------------------
// CMP
#define KP_CMP_FAIL             75
#define KP_CMP_CHECK_AFTER      76
#define KP_CMP_STATUS           77
#define KP_CMP_SERVER_WAIT      78
#define KP_CMP_ADD_KEY          79
#define KP_CMP_TYPE             80
#define KP_CMP_TRANS_ID         81
#define KP_CMP_SND_NONCE        82
#define KP_CMP_RCP_NONCE        83
#define KP_CMP_HASH_ALG         84
#define KP_CMP_MAC_ALG          85
#define KP_CMP_SND_KID          86
#define KP_CMP_SECRET           87
#define KP_CMP_EXP_KEY          88
#define KP_CMP_RCP_SUBJ         89
#define KP_CMP_GEN_OID          90
#define KP_CMP_GEN_VAL_SIZE    140
#define KP_CMP_GEN_VAL          91
#define KP_CMP_GEN_CNT          92
#define KP_CMP_SND_DN           93
#define KP_CMP_RCP_DN           94
#define KP_CMP_RR_REASON        95
//
#define KP_CUR_CRT_SECTION      96
#define KP_CRT_COUNT            97
#define KP_ENUM_CERT            98
#define KP_CMP_OTP              99
#define KP_CMP_CERTIFICATES    150
#define KP_CMP_CERTIFICATES_CA 151
//
#define KP_CMP_OVALID          154 // OptionalValidity (CRMF)
#define KP_CMP_EXT             155 // Extension (PKIX)
//------------------------------------------------------------------------------
#define CRT_SECTION_EXT  0
#define CRT_SECTION_USER 1
#define CRT_SECTION_CA   2
//------------------------------------------------------------------------------
#define REASON_keyCompromise        1
#define REASON_cACompromise         2
#define REASON_affiliationChanged   3
#define REASON_superseded           4
#define REASON_cessationOfOperation 5
#define REASON_certificateHold      6
#define REASON_removeFromCRL        8
#define REASON_privilegeWithdrawn   9
#define REASON_aACompromise        10
//------------------------------------------------------------------------------
// CRT
#define KP_CRT_USAGE           101
#define KP_CRT_PURPOSES        102
#define KP_CRT_ENUM_POLICIES   103
#define KP_CRT_VFROM           104
#define KP_CRT_VTO             105
#define KP_CRT_ISSU_DN         106
#define KP_CRT_SUBJ_DN         107
//
//------------------------------------------------------------------------------
#define KP_PKCS7_DATA_SIZE     110
#define KP_PKCS7_DATA          111
//------------------------------------------------------------------------------
// OCSP
#define KP_OCSP_REP_STATUS     120
#define KP_OCSP_REP_TIME       121
#define KP_OCSP_REP_CRT_SN     122
#define KP_OCSP_REP_CRT_STATUS 123 // 0-good, 1-revoked, 2-unknown
#define KP_OCSP_REP_REV_TIME   124
#define KP_OCSP_REP_REV_REASON 125
#define KP_OCSP_REP_THIS_UPD   126
#define KP_OCSP_REP_NEXT_UPD   127
//------------------------------------------------------------------------------
#define HP_PKCS7_BODY        20
#define HP_PKCS7_SIGN_COUNT  21
#define HP_PKCS7_CUR_SIGN    22
#define HP_PKCS9_CUR_OID     23
#define HP_PKCS9A_SIZE       24
#define HP_PKCS9A_DATA       25
#define HP_PKCS9U_SIZE       26
#define HP_PKCS9U_DATA       27
#define HP_PKCS7_DATA_SIZE   28
#define HP_PKCS7_DATA        29
#define HP_PKCS7_HASH_AID    30
#define HP_PKCS7_SI_HASH_AID 31
#define HP_PKCS7_SI_SIGN_AID 32
#define HP_PKCS7_SI_SN       33
#define HP_PKCS7_SI_DN       34
#define HP_PKCS7_CERTIFICATE 35
#define HP_PKCS7_CRT_COUNT   36
#define HP_PKCS7_ENUM_CERT   37
// for create request
#define HP_TIME_STAMP_OID    40
#define HP_TIME_STAMP_CRT    41
#define HP_TIME_STAMP_REQ    42
// for parse response
#define HP_TSTAMP_BODY       45
#define HP_TSTAMP_STSTUS     46
#define HP_TSTAMP_HASH       47
#define HP_TSTAMP_POLICIE    48
#define HP_TSTAMP_TIME       49
#define HP_TSTAMP_SN         50
#define HP_TSTAMP_DN         51
#define HP_TSTAMP_NONCE      52
//------------------------------------------------------------------------------
// For KP_CRT_USAGE:
#define CRT_KEYUSAGE_DIGSIGN  0x0080 // digitalSignature
#define CRT_KEYUSAGE_NONREPU  0x0040 // nonRepudiation
#define CRT_KEYUSAGE_KEYENCH  0x0020 // keyEncipherment
#define CRT_KEYUSAGE_DATAENC  0x0010 // dataEncipherment
#define CRT_KEYUSAGE_KEYAGRM  0x0008 // keyAgreement
#define CRT_KEYUSAGE_CERTSIG  0x0004 // keyCertSign
#define CRT_KEYUSAGE_CRLSIGN  0x0002 // cRLSign
#define CRT_KEYUSAGE_ENCONLY  0x0001 // encipherOnly
#define CRT_KEYUSAGE_DECONLY  0x8000 // decipherOnly
// For KP_CRT_PURPOSES:
#define CRT_PURPOSE_CA   0x01
#define CRT_PURPOSE_RA   0x02
#define CRT_PURPOSE_OCSP 0x04
#define CRT_PURPOSE_TSA  0x08
#define CRT_PURPOSE_DVCS 0x10
//------------------------------------------------------------------------------
#define PRIVATEKEYBLOB_PKCS8         0x30
#define PRIVATEKEYBLOB_PKCS12        0x31
#define PUBLICKEYBLOB_CERT           0x32
#define PUBLICKEYBLOB_REQ_P10        0x33
#define PUBLICKEYBLOB_REQ_P10_PEM    0x34
#define PUBLICKEYBLOB_REQ_P7         0x35
#define PUBLICKEYBLOB_REQ_P7_PEM     0x36
#define PUBLICKEYBLOB_SUBJ_KEY       0x37
#define PUBLICKEYBLOB_SUBJ_KEY_PARAM 0x38
#define PUBLICKEYBLOB_CMP            0x39
#define PUBLICKEYBLOB_CMP_B64        0x40
#define PUBLICKEYBLOB_OCSP           0x41
#define PUBLICKEYBLOB_OCSP_B64       0x42
#define PUBLICKEYBLOB_CRL            0x43
#define SIMPLEBLOB_P7                0x50
#define SIMPLEBLOB_P7_B64            0x51
//------------------------------------------------------------------------------
#define PKI_CMP_IR         0 // --Initialization Req
#define PKI_CMP_IP         1 // --Initialization Resp
#define PKI_CMP_CR         2 // --Certification Req
#define PKI_CMP_CP         3 // --Certification Resp
#define PKI_CMP_KUR        7 // --Key Update Request
#define PKI_CMP_KUP        8 // --Key Update Response
#define PKI_CMP_RR        11 // --Revocation Request
#define PKI_CMP_RP        12 // --Revocation Response
#define PKI_CMP_CCR       13 // --Cross-Cert.  Request
#define PKI_CMP_CCP       14 // --Cross-Cert.  Resp
#define PKI_CMP_PKI_CONF  19 // --Confirmation
#define PKI_CMP_GENM      21 // --General Message
#define PKI_CMP_GENP      22 // --General Response
#define PKI_CMP_ERROR     23 // --Error Message
#define PKI_CMP_CERT_CONF 24 // --Certificate confirm
#define PKI_CMP_PR        25 // --Polling request
#define PKI_CMP_PP        26 // --Polling response
//------------------------------------------------------------------------------
#define CMP_GENERAL_IT "1.3.6.1.5.5.7.4"
#define CMP_GENERAL_CRT_EXCH         CMP_GENERAL_IT".1"
#define CMP_GENERAL_CRL              CMP_GENERAL_IT".6"
#define CMP_GENERAL_PASS             CMP_GENERAL_IT".12"
#define CMP_GENERAL_IMPL_CONF        CMP_GENERAL_IT".13"
#define CMP_GENERAL_SRV_WAIT         CMP_GENERAL_IT".14"
#define CMP_GENERAL_DEP_KEY          CMP_GENERAL_IT".50.1"
#define CMP_GENERAL_GET_KEY          CMP_GENERAL_IT".50.2"
#define CMP_GENERAL_DEL_KEY          CMP_GENERAL_IT".50.3"
#define CMP_GENERAL_ADD_SECRET       CMP_GENERAL_IT".50.5"
#define CMP_GENERAL_MOD_SECRET       CMP_GENERAL_IT".50.6"
#define CMP_GENERAL_GET_SECRET       CMP_GENERAL_IT".50.7"
#define CMP_GENERAL_DEL_SECRET       CMP_GENERAL_IT".50.8"
#define CMP_GENERAL_TRANS_LIST       CMP_GENERAL_IT".50.10"
#define CMP_GENERAL_GET_OPER_CA      CMP_GENERAL_IT".50.11"
#define CMP_GENERAL_ADD_USER_DETAILS CMP_GENERAL_IT".50.14"
#define CMP_GENERAL_MOD_USER_DETAILS CMP_GENERAL_IT".50.15"
#define CMP_GENERAL_GET_USER_DETAILS CMP_GENERAL_IT".50.16"
//
#define OID_TRANSACTION_ID      "2.16.840.1.113733.1.9.7"
#define OID_PKCS9_TIMESTAMPATTR "1.2.840.113549.1.9.16.2.14"
#define OID_PKCS9_LOCAL_KEY_ID  "1.2.840.113549.1.9.21"
#define OID_PKCS9_SIGNINGTIME   "1.2.840.113549.1.9.5"
//------------------------------------------------------------------------------
#ifndef GET_ALG_CLASS
#define GET_ALG_CLASS(x) (x & (7 << 13))
#endif
#ifndef GET_ALG_TYPE
#define GET_ALG_TYPE(x)  (x & (15 << 9))
#endif
#ifndef GET_ALG_SID
#define GET_ALG_SID(x)   (x & (511))
#endif
//------------------------------------------------------------------------------
// Parameters for SIGNATURE (DH/EC)
#define ALG_SID_DH256_1024_T    50
#define ALG_SID_DH256_1024_A    51
#define ALG_SID_DH256_1024_B    52
#define ALG_SID_DH256_1024_C    53
#define ALG_SID_DH256_1024_D    54
#define ALG_SID_DH512_512T      ALG_SID_TUMAR_DH
#define ALG_SID_DH512_1024      56    // not supported
#define ALG_SID_DH512_1536      57    // not supported
// EC:
#define ALG_SID_EC256_512G_A    58
#define ALG_SID_EC256_512F      59
#define ALG_SID_EC384_768F      60
#define ALG_SID_EC521_1042F     61
#define ALG_SID_EC160_320F      62
#define ALG_SID_EC192_384F      63
#define ALG_SID_EC224_448F      73
#define ALG_SID_EC256_512G_B    64
#define ALG_SID_EC256_512G_C    65
//------------------------------------------------------------------------------
// Parameters for KEY-EXCHANGE (DH/EC)
#define ALG_SID_DH256_1024_A_Xch  66
#define ALG_SID_DH256_1024_B_Xch  67
#define ALG_SID_DH256_1024_C_Xch  68
#define ALG_SID_DH512_512T_Xch    75
// EC:
#define ALG_SID_EC256_512G_A_Xch  69
#define ALG_SID_EC256_512G_B_Xch  70
#define ALG_SID_EC256_512F_Xch    73
#define ALG_SID_EC384_768F_Xch    71
#define ALG_SID_EC521_1042F_Xch   72
// RSA:
#define ALG_SID_RSA_1024          80
#define ALG_SID_RSA_1536          81
#define ALG_SID_RSA_2048          82
#define ALG_SID_RSA_3072          83
#define ALG_SID_RSA_4096          84
//------------------------------------------------------------------------------
// KEY-EXCHANGE algorithms
#define ALG_SID_ELGAM           32
#define ALG_SID_TUMAR_DH        33
//------------------------------------------------------------------------------
// ENCRYPTION algorithms
#define ALG_SID_CRTUMAR         30 // only for support v 3.0
#define ALG_SID_TG28147         31 // only for support v 3.0
#define ALG_SID_GOST            32
#define ALG_SID_TAES128         14 // ALG_SID_AES_128
#define ALG_SID_TAES192         15 // ALG_SID_AES_192
#define ALG_SID_TAES256         16 // ALG_SID_AES_256
#define ALG_SID_TAES            17 // ALG_SID_AES
#define ALG_SID_T1DES            1 // ALG_SID_DES
#define ALG_SID_T2DES            9 // ALG_SID_3DES_112
#define ALG_SID_T3DES            3 // ALG_SID_3DES
#define ALG_SID_TRC2             2 // ALG_SID_RC2
#define ALG_SID_TRC4             1 // ALG_SID_RC4
#define ALG_SID_TRC5            13 // ALG_SID_RC5
//------------------------------------------------------------------------------
// HASH algorithms
#define ALG_SID_CPGR3411        21
#define ALG_SID_TMD2             1 // ALG_SID_MD2
#define ALG_SID_TMD4             2 // ALG_SID_MD4
#define ALG_SID_TMD5             3 // ALG_SID_MD5
#define ALG_SID_SHA_160          4 // ALG_SID_SHA1
#ifndef ALG_SID_SHA_256
#define ALG_SID_SHA_256         12 // ALG_SID_SHA_256
#endif
#ifndef ALG_SID_SHA_384
#define ALG_SID_SHA_384         13 // ALG_SID_SHA_384
#endif
#ifndef ALG_SID_SHA_512
#define ALG_SID_SHA_512         14 // ALG_SID_SHA_512
#endif
#define ALG_SID_HSTUMAR         28
#define ALG_SID_TGR3411         29
//------------------------------------------------------------------------------
// IMIT algorithms
#define ALG_SID_CRTUMAR_IMIT    30 // only for support v 3.0
#define ALG_SID_TG28147_IMIT    31 // only for support v 3.0
#define ALG_SID_GOST_IMIT       32
#define ALG_SID_TAES_IMIT       33
//------------------------------------------------------------------------------
// HMAC algorithms
#define ALG_SID_TMD2_HMAC       40
#define ALG_SID_TMD4_HMAC       41
#define ALG_SID_TMD5_HMAC       42
#define ALG_SID_SHA_160_HMAC    43
#define ALG_SID_SHA_256_HMAC    44
#define ALG_SID_SHA_384_HMAC    45
#define ALG_SID_SHA_512_HMAC    46
#define ALG_SID_TGR3411_HMAC    47
#define ALG_SID_CPGR3411_HMAC   48
//------------------------------------------------------------------------------
// SIGNATURE algorithms
#define ALG_SID_SGRSA            0   // ALG_SID_RSA_ANY
#define ALG_SID_SGTUMAR         28
#define ALG_SID_TGR3410         29
//------------------------------------------------------------------------------
#define ALG_SID_CMP_KEY         90
//------------------------------------------------------------------------------
// CALG-s:
//------------------------------------------------------------------------------
// Parameters for SIGNATURE (DH/EC)
#define CALG_DH256_1024_T       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH256_1024_T) // Vista
#define CALG_DH256_1024_A       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH256_1024_A)
#define CALG_DH256_1024_B       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH256_1024_B)
#define CALG_DH256_1024_C       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH256_1024_C)
#define CALG_DH256_1024_D       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH256_1024_D)
#define CALG_DH512_512T         (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH512_512T)   // MGD
#define CALG_DH512_1024         (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH512_1024)   // not supported
#define CALG_DH512_1536         (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_DH512_1536)   // not supported
// EC:
#define CALG_EC256_512G_A       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_EC256_512G_A)
#define CALG_EC256_512G_B       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_EC256_512G_B)
#define CALG_EC256_512G_C       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_EC256_512G_C)
#define CALG_EC160_320F         (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_EC160_320F)
#define CALG_EC192_384F         (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_EC192_384F)
#define CALG_EC224_448F         (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_EC224_448F)
#define CALG_EC256_512F         (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_EC256_512F)
#define CALG_EC384_768F         (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_EC384_768F)
#define CALG_EC521_1042F        (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH|ALG_SID_EC521_1042F)
// RSA:
#define CALG_RSA_1024           (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA|ALG_SID_RSA_1024)
#define CALG_RSA_1536           (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA|ALG_SID_RSA_1536)
#define CALG_RSA_2048           (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA|ALG_SID_RSA_2048)
#define CALG_RSA_3072           (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA|ALG_SID_RSA_3072)
#define CALG_RSA_4096           (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA|ALG_SID_RSA_4096)
//------------------------------------------------------------------------------
// Parameters for KEY-EXCHANGE (DH/EC)
#define CALG_DH256_1024_A_Xch   (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_DH256_1024_A_Xch)
#define CALG_DH256_1024_B_Xch   (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_DH256_1024_B_Xch)
#define CALG_DH256_1024_C_Xch   (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_DH256_1024_C_Xch)
#define CALG_DH512_512T_Xch     (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_DH512_512T_Xch)
// EC:
#define CALG_EC256_512G_A_Xch   (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_EC256_512G_A_Xch)
#define CALG_EC256_512G_B_Xch   (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_EC256_512G_B_Xch)
#define CALG_EC256_512F_Xch     (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_EC256_512F_Xch)
#define CALG_EC384_768F_Xch     (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_EC384_768F_Xch)
#define CALG_EC521_1042F_Xch    (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_EC521_1042F_Xch)
// RSA:
#define CALG_RSA_1024_Xch       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_RSA_1024)
#define CALG_RSA_1536_Xch       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_RSA_1536)
#define CALG_RSA_2048_Xch       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_RSA_2048)
#define CALG_RSA_3072_Xch       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_RSA_3072)
#define CALG_RSA_4096_Xch       (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_RSA_4096)
//------------------------------------------------------------------------------
// KEY-EXCHANGE algorithms
#define CALG_ELGAM              (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_ELGAM)
#define CALG_TUMARDH            (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DH |ALG_SID_TUMAR_DH)
#define CALG_TUMARRSA           (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA|ALG_SID_RSA_ANY) // CALG_RSA_KEYX
#define CALG_CMP_KEY            (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_ANY|ALG_SID_CMP_KEY)
//------------------------------------------------------------------------------
// ENCRYPTION algorithms
// Default MODE: CRYPT_MODE_CFB
// Other MODEs:  CRYPT_MODE_ECB/CBC/CNT/OFB
#define CALG_CRTUMAR            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_STREAM|ALG_SID_CRTUMAR) // only for support v 3.0
#define CALG_TG28147            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_STREAM|ALG_SID_TG28147) // only for support v 3.0
#define CALG_GOST               (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_GOST)
#define CALG_TAES128            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_TAES128)
#define CALG_TAES192            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_TAES192)
#define CALG_TAES256            (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_TAES256)
#define CALG_TAES               (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_TAES)
#define CALG_T1DES              (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_T1DES)
#define CALG_T2DES              (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_T2DES)
#define CALG_T3DES              (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_T3DES)
#define CALG_TRC2               (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_TRC2)
#define CALG_TRC4               (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_STREAM|ALG_SID_TRC4)
#define CALG_TRC5               (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_TRC5)
//------------------------------------------------------------------------------
// HASH algorithms
#define CALG_CPGR3411           (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_CPGR3411)
#define CALG_TMD2               (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_TMD2)
#define CALG_TMD4               (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_TMD4)
#define CALG_TMD5               (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_TMD5)
#define CALG_SHA_160            (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_SHA_160)
#ifndef CALG_SHA_256
#define CALG_SHA_256            (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_SHA_256)
#endif
#ifndef CALG_SHA_384
#define CALG_SHA_384            (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_SHA_384)
#endif
#ifndef CALG_SHA_512
#define CALG_SHA_512            (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_SHA_512)
#endif
#define CALG_HSTUMAR            (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_HSTUMAR)
#define CALG_TGR3411            (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_TGR3411)
//------------------------------------------------------------------------------
// IMIT algorithms
// Default MODE: CRYPT_MODE_IMT  (imitovstavka)
// Other MODEs:  CRYPT_MODE_X919 (Retail MAC)
#define CALG_CRTUMAR_IMIT       (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_CRTUMAR) // only for support v 3.0
#define CALG_TG28147_IMIT       (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_TG28147) // only for support v 3.0
#define CALG_GOST_IMIT          (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_GOST)
#define CALG_TAES128_IMIT       (ALG_CLASS_HASH|ALG_TYPE_BLOCK|ALG_SID_TAES128)
#define CALG_TAES192_IMIT       (ALG_CLASS_HASH|ALG_TYPE_BLOCK|ALG_SID_TAES192)
#define CALG_TAES256_IMIT       (ALG_CLASS_HASH|ALG_TYPE_BLOCK|ALG_SID_TAES256)
#define CALG_TAES_IMIT          (ALG_CLASS_HASH|ALG_TYPE_BLOCK|ALG_SID_TAES)
#define CALG_T1DES_IMIT         (ALG_CLASS_HASH|ALG_TYPE_BLOCK|ALG_SID_T1DES)
#define CALG_T2DES_IMIT         (ALG_CLASS_HASH|ALG_TYPE_BLOCK|ALG_SID_T2DES)
#define CALG_T3DES_IMIT         (ALG_CLASS_HASH|ALG_TYPE_BLOCK|ALG_SID_T3DES)
#define CALG_TRC2_IMIT          (ALG_CLASS_HASH|ALG_TYPE_BLOCK|ALG_SID_TRC2)
#define CALG_TRC5_IMIT          (ALG_CLASS_HASH|ALG_TYPE_BLOCK|ALG_SID_TRC5)
//------------------------------------------------------------------------------
// HMAC algorithm
#define CALG_TMD2_HMAC          (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_TMD2_HMAC)
#define CALG_TMD4_HMAC          (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_TMD4_HMAC)
#define CALG_TMD5_HMAC          (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_TMD5_HMAC)
#define CALG_SHA_160_HMAC       (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_SHA_160_HMAC)
#define CALG_SHA_256_HMAC       (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_SHA_256_HMAC)
#define CALG_SHA_384_HMAC       (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_SHA_384_HMAC)
#define CALG_SHA_512_HMAC       (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_SHA_512_HMAC)
#define CALG_TGR3411_HMAC       (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_TGR3411_HMAC)
#define CALG_CPGR3411_HMAC      (ALG_CLASS_HASH|ALG_TYPE_ANY|ALG_SID_CPGR3411_HMAC)
//------------------------------------------------------------------------------
// SIGNATURE algorithms
#define CALG_SGTUMAR            (ALG_CLASS_SIGNATURE|ALG_TYPE_ANY|ALG_SID_SGTUMAR)   // not supported
#define CALG_SGRSA              (ALG_CLASS_SIGNATURE|ALG_TYPE_RSA|ALG_SID_SGRSA)     // CALG_RSA_SIGN
#define CALG_TGR3410            (ALG_CLASS_SIGNATURE|ALG_TYPE_ANY|ALG_SID_TGR3410)
#define CALG_CTRK1073           (ALG_CLASS_SIGNATURE|ALG_TYPE_ANY|30)                // not supported
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
// OID-s:
//------------------------------------------------------------------------------
// Parameters for SIGNATURE (DH/EC)
#define szOID_DH256_1024_T      "1.3.6.1.4.1.6801.1.5.1"    // Vista
#define szOID_DH256_1024_A      "1.3.6.1.4.1.6801.1.5.2"    
#define szOID_DH256_1024_B      "1.3.6.1.4.1.6801.1.5.3"    
#define szOID_DH256_1024_C      "1.3.6.1.4.1.6801.1.5.4"    
#define szOID_DH256_1024_D      "1.3.6.1.4.1.6801.1.5.5"    
#define szOID_DH512_512T        szOID_TUMARDH               // MGD
// EC:
#define szOID_EC256_512G_A      "1.3.6.1.4.1.6801.1.5.8"
#define szOID_EC256_512F        "1.3.6.1.4.1.6801.1.5.9"
#define szOID_EC384_768F        "1.3.6.1.4.1.6801.1.5.10"
#define szOID_EC521_1042F       "1.3.6.1.4.1.6801.1.5.11"
#define szOID_EC160_320F        "1.3.6.1.4.1.6801.1.5.12"
#define szOID_EC192_384F        "1.3.6.1.4.1.6801.1.5.13"
#define szOID_EC224_448F        "1.3.6.1.4.1.6801.1.5.16"
#define szOID_EC256_512G_B      "1.3.6.1.4.1.6801.1.5.14"
#define szOID_EC256_512G_C      "1.3.6.1.4.1.6801.1.5.15"
// RSA:
#define szOID_RSA_1024          "1.3.6.1.4.1.6801.1.5.20"
#define szOID_RSA_1536          "1.3.6.1.4.1.6801.1.5.21"
#define szOID_RSA_2048          "1.3.6.1.4.1.6801.1.5.22"
#define szOID_RSA_3072          "1.3.6.1.4.1.6801.1.5.23"
#define szOID_RSA_4096          "1.3.6.1.4.1.6801.1.5.24"
//------------------------------------------------------------------------------
// Parameters for KEY-EXCHANGE (DH/EC)
#define szOID_DH256_1024_A_Xch  "1.3.6.1.4.1.6801.1.8.2"
#define szOID_DH256_1024_B_Xch  "1.3.6.1.4.1.6801.1.8.3"
#define szOID_DH256_1024_C_Xch  "1.3.6.1.4.1.6801.1.8.4"
#define szOID_DH512_512T_Xch    "1.3.6.1.4.1.6801.1.8.1"
// EC:
#define szOID_EC256_512G_A_Xch  "1.3.6.1.4.1.6801.1.8.8"
#define szOID_EC256_512F_Xch    "1.3.6.1.4.1.6801.1.8.9"
#define szOID_EC256_512G_B_Xch  "1.3.6.1.4.1.6801.1.8.14"
#define szOID_EC384_768F_Xch    "1.3.6.1.4.1.6801.1.8.10"
#define szOID_EC521_1042F_Xch   "1.3.6.1.4.1.6801.1.8.15"
// RSA:
#define szOID_RSA_1024_Xch      "1.3.6.1.4.1.6801.1.8.20"
#define szOID_RSA_1536_Xch      "1.3.6.1.4.1.6801.1.8.21"
#define szOID_RSA_2048_Xch      "1.3.6.1.4.1.6801.1.8.22"
#define szOID_RSA_3072_Xch      "1.3.6.1.4.1.6801.1.8.23"
#define szOID_RSA_4096_Xch      "1.3.6.1.4.1.6801.1.8.24"
//------------------------------------------------------------------------------
// KEY-EXCHANGE algorithms
#define szOID_ELGAM             "1.3.6.1.4.1.6801.1.3.4"
#define szOID_TUMARDH           "1.3.6.1.4.1.6801.1.4.4"
//------------------------------------------------------------------------------
// ENCRYPTION algorithms
#define szOID_CRTUMAR           "1.3.6.1.4.1.6801.1.1.4" // only for support v 3.0
#define szOID_TG28147           "1.3.6.1.4.1.6801.1.2.4"
#define szOID_GOST              "1.3.6.1.4.1.6801.1.20.1"
#define szOID_TAES128           "2.16.840.1.101.3.4.1.2"
#define szOID_TAES192           "2.16.840.1.101.3.4.1.22"
#define szOID_TAES256           "2.16.840.1.101.3.4.1.42"
#define szOID_TAES              szOID_TAES128
#define szOID_TAES128_ECB       "2.16.840.1.101.3.4.1.1"
#define szOID_TAES192_ECB       "2.16.840.1.101.3.4.1.21"
#define szOID_TAES256_ECB       "2.16.840.1.101.3.4.1.41"
#define szOID_TAES128_OFB       "2.16.840.1.101.3.4.1.3"
#define szOID_TAES192_OFB       "2.16.840.1.101.3.4.1.23"
#define szOID_TAES256_OFB       "2.16.840.1.101.3.4.1.43"
#define szOID_TAES128_CFB       "2.16.840.1.101.3.4.1.4"
#define szOID_TAES192_CFB       "2.16.840.1.101.3.4.1.24"
#define szOID_TAES256_CFB       "2.16.840.1.101.3.4.1.44"
#define szOID_T1DES             szOID_OIWSEC_desCBC
#define szOID_T1DES_ECB         szOID_OIWSEC_desECB
#define szOID_T1DES_OFB         szOID_OIWSEC_desOFB
#define szOID_T1DES_CFB         szOID_OIWSEC_desCFB
#define szOID_T2DES             szOID_OIWSEC_desEDE
#define szOID_T3DES             szOID_RSA_DES_EDE3_CBC
#define szOID_TRC2              szOID_RSA_RC2CBC
#define szOID_TRC4              szOID_RSA_RC4
#define szOID_TRC5              szOID_RSA_RC5_CBCPad
//------------------------------------------------------------------------------
#define szOID_GOST_CBC          "1.3.6.1.4.1.6801.1.20.1.1" // CRYPT_MODE_CBC (1)
#define szOID_GOST_ECB          "1.3.6.1.4.1.6801.1.20.1.2" // CRYPT_MODE_ECB (2)
#define szOID_GOST_OFB          "1.3.6.1.4.1.6801.1.20.1.3" // CRYPT_MODE_OFB (3)
#define szOID_GOST_CFB          "1.3.6.1.4.1.6801.1.20.1.4" // CRYPT_MODE_CFB (4) // default
#define szOID_GOST_CNT          "1.3.6.1.4.1.6801.1.20.1.7"
#define szOID_GOST_CFB_SSL      "1.3.6.1.4.1.6801.1.21" // OpenSSL
//------------------------------------------------------------------------------
/*
2.16.840.1.101.3.4.1.1  - id-aes128-ECB 
2.16.840.1.101.3.4.1.2  - id-aes128-CBC 
2.16.840.1.101.3.4.1.3  - id-aes128-OFB 
2.16.840.1.101.3.4.1.4  - id-aes128-CFB 
2.16.840.1.101.3.4.1.21 - id-aes192-ECB 
2.16.840.1.101.3.4.1.22 - id-aes192-CBC 
2.16.840.1.101.3.4.1.23 - id-aes192-OFB 
2.16.840.1.101.3.4.1.24 - id-aes192-CFB 
2.16.840.1.101.3.4.1.41 - id-aes256-ECB 
2.16.840.1.101.3.4.1.42 - id-aes256-CBC 
2.16.840.1.101.3.4.1.43 - id-aes256-OFB 
2.16.840.1.101.3.4.1.44 - id-aes256-CFB 
*/
//------------------------------------------------------------------------------
// HASH algorithms
#define szOID_HSTUMAR           "1.3.6.1.4.1.6801.1.1.1"
#define szOID_TGR3411           "1.3.6.1.4.1.6801.1.2.1"
#define szOID_CPGR3411          "1.2.643.2.2.9" 
#define szOID_TMD2              szOID_RSA_MD2
#define szOID_TMD4              szOID_RSA_MD4
#define szOID_TMD5              szOID_RSA_MD5
#define szOID_SHA_160           szOID_OIWSEC_sha1
#define szOID_SHA_256           "2.16.840.1.101.3.4.2.1"
#define szOID_SHA_384           "2.16.840.1.101.3.4.2.2"
#define szOID_SHA_512           "2.16.840.1.101.3.4.2.3"
#define szOID_SHA_MD5           "1.3.6.1.4.1.6801.1.1.5"
//------------------------------------------------------------------------------
// IMIT algorithms
#define szOID_CRTUMAR_IMIT      "1.3.6.1.4.1.6801.1.1.3" // only for support v 3.0
#define szOID_TG28147_IMIT      "1.3.6.1.4.1.6801.1.2.3" // only for support v 3.0
#define szOID_GOST_IMIT         "1.3.6.1.4.1.6801.1.21.1"
#define szOID_TAES128_IMIT      "1.3.6.1.4.1.6801.1.21.2"
#define szOID_TAES192_IMIT      "1.3.6.1.4.1.6801.1.21.3"
#define szOID_TAES256_IMIT      "1.3.6.1.4.1.6801.1.21.4"
#define szOID_TAES_IMIT         szOID_TAES128_IMIT
#define szOID_T1DES_IMIT        szOID_OIWSEC_desMAC
#define szOID_T2DES_IMIT        "1.3.6.1.4.1.6801.1.21.6"
#define szOID_T3DES_IMIT        "1.3.6.1.4.1.6801.1.21.7"
#define szOID_TRC2_IMIT         "1.3.6.1.4.1.6801.1.21.8"
#define szOID_TRC5_IMIT         "1.3.6.1.4.1.6801.1.21.10"
//------------------------------------------------------------------------------
// HMAC algorithm
#define szOID_TMD2_HMAC        "1.3.6.1.4.1.6801.1.22.1"
#define szOID_TMD4_HMAC        "1.3.6.1.4.1.6801.1.22.2"
#define szOID_TMD5_HMAC        "1.3.6.1.5.5.8.1.1"
#define szOID_SHA_HMAC         "1.3.6.1.5.5.8.1.2"
#define szOID_SHA_160_HMAC     "1.2.840.113549.2.7"
#define szOID_SHA_224_HMAC     "1.2.840.113549.2.8"
#define szOID_SHA_256_HMAC     "1.2.840.113549.2.9"
#define szOID_SHA_384_HMAC     "1.2.840.113549.2.10"
#define szOID_SHA_512_HMAC     "1.2.840.113549.2.11"
#define szOID_TGR3411_HMAC     "1.3.6.1.4.1.6801.1.22.8"
#define szOID_CPGR3411_HMAC    "1.3.6.1.4.1.6801.1.22.9"
//------------------------------------------------------------------------------
// SIGNATURE algorithms
#define szOID_SGTUMAR           "1.3.6.1.4.1.6801.1.1.2"
#define szOID_TGR3410           "1.3.6.1.4.1.6801.1.2.2"
#define szOID_SGRSA             szOID_RSA_SHA1RSA
//------------------------------------------------------------------------------
#define szOID_TGR3411_TGR3410   szOID_TGR3410                 // not supported
#define szOID_CPGR3411_TGR3410  "1.3.6.1.4.1.6801.1.3.2"      // not supported
#define szOID_SHA384_TGR3410    "1.3.6.1.4.1.6801.1.5.2"      // not supported
#define szOID_SHA512_TGR3410    "1.3.6.1.4.1.6801.1.6.2"      // not supported
#define szOID_CTRK1073          "1.3.6.1.4.1.6801.1.2.5"      // not supported
//------------------------------------------------------------------------------
// Gost28147 Param Set
#define szOID_PARAM_GOST_T      "1.2.643.2.2.31.0"       // GOST 28147-89 / Gost28147_TestParamSet
#define szOID_PARAM_GOST_G      "1.3.6.1.4.1.6801.1.2.4" // GOST 28147-89 / Gost28147_GammaParamSet (Default)
#define szOID_PARAM_GOST_A      "1.2.643.2.2.31.1"       // GOST 28147-89 / Gost28147_CryptoProParamSetA
#define szOID_PARAM_GOST_B      "1.2.643.2.2.31.2"       // GOST 28147-89 / Gost28147_CryptoProParamSetB
#define szOID_PARAM_GOST_C      "1.2.643.2.2.31.3"       // GOST 28147-89 / Gost28147_CryptoProParamSetC
#define szOID_PARAM_GOST_D      "1.2.643.2.2.31.4"       // GOST 28147-89 / Gost28147_CryptoProParamSetD
//------------------------------------------------------------------------------
// SSL
#define szOID_PCT1_MASTER       "1.3.6.1.4.1.6801.1.23.1"
#define szOID_SSL2_MASTER       "1.3.6.1.4.1.6801.1.23.2"
#define szOID_SSL3_MASTER       "1.3.6.1.4.1.6801.1.23.3"
#define szOID_TLS1_MASTER       "1.3.6.1.4.1.6801.1.23.4"
#define szOID_SCHANNEL_ENC      "1.3.6.1.4.1.6801.1.23.5"
#define szOID_SCHANNEL_MAC      "1.3.6.1.4.1.6801.1.23.6"
#define szOID_MASTER_HASH       "1.3.6.1.4.1.6801.1.23.7"
#define szOID_TLS1_PRF          "1.3.6.1.4.1.6801.1.23.8"
//------------------------------------------------------------------------------
#ifndef CALG_ECDSA
#define ALG_SID_ECDSA 3
#define CALG_ECDSA (ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_ECDSA)
#endif
//------------------------------------------------------------------------------
#ifndef szOID_ECDSA_SHA1
#define szOID_ECDSA_SHA1        "1.2.840.10045.4.1"
#define szOID_ECDSA_SPECIFIED   "1.2.840.10045.4.3"
#define szOID_ECDSA_SHA256      "1.2.840.10045.4.3.2"
#define szOID_ECDSA_SHA384      "1.2.840.10045.4.3.3"
#define szOID_ECDSA_SHA512      "1.2.840.10045.4.3.4"
#endif
//------------------------------------------------------------------------------
#ifndef szOID_ECC_PUBLIC_KEY
#define szOID_ECC_PUBLIC_KEY    "1.2.840.10045.2.1"
#endif
#ifndef szOID_ECC_CURVE_P160
#define szOID_ECC_CURVE_P160    "1.3.132.0.8"
#endif
#ifndef szOID_ECC_CURVE_P192
#define szOID_ECC_CURVE_P192    "1.2.840.10045.3.1"
#endif
#ifndef szOID_ECC_CURVE_P224
#define szOID_ECC_CURVE_P224    "1.3.132.0.33"
#endif
#ifndef szOID_ECC_CURVE_P256
#define szOID_ECC_CURVE_P256    "1.2.840.10045.3.1.7"
#endif
#ifndef szOID_ECC_CURVE_P384
#define szOID_ECC_CURVE_P384    "1.3.132.0.34"
#endif
#ifndef szOID_ECC_CURVE_P521
#define szOID_ECC_CURVE_P521    "1.3.132.0.35"
#endif
#ifndef szOID_ECC_CURVE_P192_V1
#define szOID_ECC_CURVE_P192_V1 "1.2.840.10045.3.1.1"
#endif
#ifndef szOID_ECC_CURVE_P192_V2
#define szOID_ECC_CURVE_P192_V2 "1.2.840.10045.3.1.2"
#endif
#ifndef szOID_ECC_CURVE_P192_V3
#define szOID_ECC_CURVE_P192_V3 "1.2.840.10045.3.1.3"
#endif
//------------------------------------------------------------------------------
#define szOID_PKCS_DATA "1.2.840.113549.1.7.1"
#define szOID_PKCS_SIGN "1.2.840.113549.1.7.2"
#define szOID_PKCS_ENVL "1.2.840.113549.1.7.3"
#define szOID_PKCS_HASH "1.2.840.113549.1.7.5"
#define szOID_PKCS_ENCR "1.2.840.113549.1.7.6"
//------------------------------------------------------------------------------
#define TSIZE_MAXKEY            512
#define TSIZE_MAXALPHA          128
#define TSIZE_MINALPHA          20
#define TSIZE_SESKEY            32
#define TSIZE_MAXSESKEY         128
#define TSIZE_SP                8
#define TSIZE_MAXHASH           64
#define TSIZE_MINHASH           4
#define TSIZE_IMIT              16
#define TSIZE_SHA1              20
#define TSIZE_SHA256            32
#define TSIZE_SHA384            48
#define TSIZE_SHA512            64
#define TSIZE_HASH              32
#define TSIZE_IV_GOST           TSIZE_SP
#define TSIZE_IV_AES           (TSIZE_SP*2)
//------------------------------------------------------------------------------
#ifndef WIND32
#if defined HPXX
#define CSP_LIB_LINK   "/usr/lib/libcptumar.4.0.sl"
#define CSP_LIB_LINK_R "/usr/lib/libcptumar.4.0_r.sl"
#elif defined DEC64
#define CSP_LIB_LINK   "/usr/shlib/libcptumar.4.0.so"
#define CSP_LIB_LINK_R "/usr/shlib/libcptumar.4.0_r.so"
#elif defined LINUX64
#define CSP_LIB_LINK   "/lib64/libcptumar.so.4.0"
#define CSP_LIB_LINK_R "/lib64/libcptumar_r.so.4.0"
#elif defined MACXX
#define CSP_LIB_LINK   "/usr/lib/libcptumar.4.0.dylib"
#define CSP_LIB_LINK_R "/usr/lib/libcptumar_r.4.0.dylib"
#else
#define CSP_LIB_LINK   "/lib/libcptumar.so.4.0"
#define CSP_LIB_LINK_R "/lib/libcptumar_r.so.4.0"
#endif
#endif
//------------------------------------------------------------------------------
#define OBJECT_ALG_TYPE_DH  1
#define OBJECT_ALG_TYPE_EC  2
#define OBJECT_ALG_TYPE_RSA 3
//
struct CSP_ALG_OBJECT {
 int code;
 ALG_ID ai;
 int sec_bits;
 int pub_bits;
 const char *oid;
 const char *name;
 int obj_alg_type; // OBJECT_ALG_TYPE_DH / OBJECT_ALG_TYPE_EC / OBJECT_ALG_TYPE_RSA
 int max_level;    // 0-4
 unsigned char *p; int sp; // p
 unsigned char *q; int sq; // q
 unsigned char *a; int sa; // a
 unsigned char *b; int sb; // b  (if EC)
 unsigned char *x; int sx; // px (if EC)
 unsigned char *y; int sy; // py (if EC)
};
//------------------------------------------------------------------------------
#define CNT_STATE_OK    0
#define CNT_STATE_WAIT  1
#define CNT_STATE_BLOCK 2
typedef struct _CNT_PRIVATE_KEY {
 HCRYPTKEY hKey;
 ALG_ID    algID;
 BOOL      exp;
 DWORD     state;
 CHAR     *szOID;
 CHAR     *createTime;
 DATA_BLOB serialNum;
 DATA_BLOB publicKey;
 CERT_BLOB certificate;
} CNT_PRIVATE_KEY;
//------------------------------------------------------------------------------
typedef struct _CNT_CERT {
 ALG_ID algID;
 DATA_BLOB serialNum;
 CERT_BLOB certificate;
} CNT_CERT;
//------------------------------------------------------------------------------
typedef struct _KEYSTORAGE_INFO {
 CHAR *Name;
 CHAR *AltName;
} KEYSTORAGE_INFO;
//------------------------------------------------------------------------------
typedef struct _PROFILE_URL {
 CHAR *Profile;
 CHAR *Url;
} PROFILE_URL;
//------------------------------------------------------------------------------
typedef struct _OPER_CONTAINER {
 CHAR *UrlFrom;
 CHAR *UrlTo;
} OPER_CONTAINER;
//------------------------------------------------------------------------------
typedef struct _USERLICENSE {
  char *User;
  char *Created;
  char *Expires;
  char *Name;
  char *Level;
} USERLICENSE;
//------------------------------------------------------------------------------
typedef struct CONTINFO {
  char name [128];
  char dev  [64];
  char user [128];
  char pass [128];
  char param[260];
  char cont [32];
  int  alg_exch;
  int  alg_sign;
  unsigned char sn[64];
  int  sn_size;
} ContInfo;
//------------------------------------------------------------------------------
//#ifndef __OBJC__
//typedef struct CONTINFOEX  : public ContInfo {
//  char alt_dev[128];
//  char Url[512];
//} ContInfoEx;
//#else
typedef struct CONTINFOEX {
  char name [128];
  char dev  [64];
  char user [128];
  char pass [128];
  char param[260];
  char cont [32];
  int  alg_exch;
  int  alg_sign;
  unsigned char sn[64];
  int  sn_size;
  char alt_dev[128];
  char Url[512];
} ContInfoEx;
//#endif
//
typedef struct _OBJECT_INFO_BIN {
 DATA_BLOB object;
 DATA_BLOB data;
} ObjectInfoBin_t;
//
typedef struct _OBJECT_INFO_STR {
 DATA_BLOB object;
 CHAR data[520];
} ObjectInfoStr_t;
//
//==============================================================================
#ifdef  __cplusplus
extern "C" {
#endif
//==============================================================================
//    CSP Connection Functions
//------------------------------------------------------------------------------
/*
 -	CPAcquireContext
 -
 *	Purpose:
 *               The CPAcquireContext function is used to acquire a context
 *               handle to a cryptograghic service provider (CSP).
 *
 *	Parameters:
 *               OUT phProv        -  Handle to a CSP
 *               OUT pszIdentity   -  Pointer to a string which is the
 *                                    identity of the logged on user
 *               IN  dwFlags       -  Flags values
 *               IN  pVTable       -  Pointer to table of function pointers
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPAcquireContext)
( HCRYPTPROV * phProv,
  CHAR * pszContainer,
  DWORD dwFlags,
  PVTableProvStruc pVTable);
#ifndef LOADLIBRARY
BOOL WINAPI CPAcquireContext
( HCRYPTPROV * phProv,
  CHAR * pszContainer,
  DWORD dwFlags,
  PVTableProvStruc pVTable);
#endif
//------------------------------------------------------------------------------
/*
 -	CPGetProvParam
 -
 *	Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a provider
 *
 *	Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      dwParam    -  Parameter number
 *               IN      pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPGetProvParam)
( HCRYPTPROV hProv,
  DWORD dwParam,
  BYTE * pbData,
  DWORD * pdwDataLen,
  DWORD dwFlags);
#ifndef LOADLIBRARY
BOOL WINAPI CPGetProvParam
( HCRYPTPROV hProv,
  DWORD dwParam,
  BYTE * pbData,
  DWORD * pdwDataLen,
  DWORD dwFlags);
#endif
//------------------------------------------------------------------------------
/*
 -      CPReleaseContext
 -
 *      Purpose:
 *               The CPReleaseContext function is used to release a
 *               context created by CrytAcquireContext.
 *
 *     Parameters:
 *               IN  phProv        -  Handle to a CSP
 *               IN  dwFlags       -  Flags values
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPReleaseContext)
( HCRYPTPROV hProv,
  DWORD dwFlags);
#ifndef LOADLIBRARY
BOOL WINAPI CPReleaseContext
( HCRYPTPROV hProv,
  DWORD dwFlags);
#endif
//------------------------------------------------------------------------------
/*
 -	CPSetProvParam
 -
 *	Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a provider
 *
 *	Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPSetProvParam)
( HCRYPTPROV hProv,
  DWORD dwParam,
  BYTE * pbData,
  DWORD dwFlags);
#ifndef LOADLIBRARY
BOOL WINAPI CPSetProvParam
( HCRYPTPROV hProv,
  DWORD dwParam,
  BYTE * pbData,
  DWORD dwFlags);
#endif
//==============================================================================
//    Key Generation and Exchange Functions
//------------------------------------------------------------------------------
/*
 -	CPDeriveKey
 -
 *	Purpose:
 *                Derive cryptographic keys from base data
 *
 *	Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      Algid      -  Algorithm identifier
 *               IN      hHash      -  Handle to hash
 *               IN      dwFlags    -  Flags values
 *               OUT     phKey      -  Handle to a generated key
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPDeriveKey)
( HCRYPTPROV hProv,
  ALG_ID AlgId,
  HCRYPTHASH hBaseData,
  DWORD dwFlags,
  HCRYPTKEY * phKey);
#ifndef LOADLIBRARY
BOOL WINAPI CPDeriveKey
( HCRYPTPROV hProv,
  ALG_ID AlgId,
  HCRYPTHASH hBaseData,
  DWORD dwFlags,
  HCRYPTKEY * phKey);
#endif
//------------------------------------------------------------------------------
/*
 -	CPDestroyKey
 -
 *	Purpose:
 *                Destroys the cryptographic key that is being referenced
 *                with the hKey parameter
 *
 *	Parameters:
 *               IN      hProv  -  Handle to a CSP
 *               IN      hKey   -  Handle to a key
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPDestroyKey)
( HCRYPTPROV hProv,
  HCRYPTKEY hKey);
#ifndef LOADLIBRARY
BOOL WINAPI CPDestroyKey
( HCRYPTPROV hProv,
  HCRYPTKEY hKey);
#endif
//------------------------------------------------------------------------------
/*
 -	CPDuplicateKey
 -
 *	Purpose:
 *                CPDuplicateKey
 *
 *	Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hKey       -  Handle to a key
 *               IN      pdwReserved-  Reserved
 *               IN      dwFlags    -  Flags values
 *               OUT     phKey      -  Handle to a duplicate key
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPDuplicateKey)
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  DWORD * pdwReserved,
  DWORD dwFlags,
  HCRYPTKEY * phKey);
#ifndef LOADLIBRARY
BOOL WINAPI CPDuplicateKey
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  DWORD * pdwReserved,
  DWORD dwFlags,
  HCRYPTKEY * phKey);
#endif
//------------------------------------------------------------------------------
/*
 -	CPExportKey
 -
 *	Purpose:
 *                Export cryptographic keys out of a CSP in a secure manner
 *
 *
 *	Parameters:
 *               IN  hProv      - Handle to the CSP user
 *               IN  hKey       - Handle to the key to export
 *               IN  hPubKey    - Handle to the exchange public key value of
 *                                the destination user
 *               IN  dwBlobType - Type of key blob to be exported
 *               IN  dwFlags -    Flags values
 *               OUT pbData -     Key blob data
 *               OUT pdwDataLen - Length of key blob in bytes
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPExportKey)
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  HCRYPTKEY hExpKey,
  DWORD dwBlobType,
  DWORD dwFlags,
  BYTE * pbData,
  DWORD * pdwDataLen);
#ifndef LOADLIBRARY
BOOL WINAPI CPExportKey
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  HCRYPTKEY hExpKey,
  DWORD dwBlobType,
  DWORD dwFlags,
  BYTE * pbData,
  DWORD * pdwDataLen);
#endif
//------------------------------------------------------------------------------
/*
 -	CPGenKey
 -
 *	Purpose:
 *                Generate cryptographic keys
 *
 *	Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      Algid   -  Algorithm identifier
 *               IN      dwFlags -  Flags values
 *               OUT     phKey   -  Handle to a generated key
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPGenKey)
( HCRYPTPROV hProv,
  ALG_ID AlgId,
  DWORD dwFlags,
  HCRYPTKEY * phKey);
#ifndef LOADLIBRARY
BOOL WINAPI CPGenKey
( HCRYPTPROV hProv,
  ALG_ID AlgId,
  DWORD dwFlags,
  HCRYPTKEY * phKey);
#endif
//------------------------------------------------------------------------------
/*
 -	CPGenRandom
 -
 *	Purpose:
 *                Used to fill a buffer with random bytes
 *
 *	Parameters:
 *               IN  hProv      -  Handle to the user identifcation
 *               OUT pbBuffer   -  Pointer to the buffer where the random
 *                                 bytes are to be placed
 *               IN  dwLen      -  Number of bytes of random data requested
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPGenRandom)
( HCRYPTPROV hProv,
  DWORD dwLen,
  BYTE * pbBuffer);
#ifndef LOADLIBRARY
BOOL WINAPI CPGenRandom
( HCRYPTPROV hProv,
  DWORD dwLen,
  BYTE * pbBuffer);
#endif
//------------------------------------------------------------------------------
/*
 -	CPGetKeyParam
 -
 *	Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a key
 *
 *	Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hKey       -  Handle to a key
 *               IN      dwParam    -  Parameter number
 *               IN      pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPGetKeyParam)
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  DWORD dwParam,
  BYTE * pbData,
  DWORD * pdwDataLen,
  DWORD dwFlags);
#ifndef LOADLIBRARY
BOOL WINAPI CPGetKeyParam
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  DWORD dwParam,
  BYTE * pbData,
  DWORD * pdwDataLen,
  DWORD dwFlags);
#endif
//------------------------------------------------------------------------------
/*
 -	CPGetUserKey
 -
 *	Purpose:
 *                Gets a handle to a permanent user key
 *
 *	Parameters:
 *               IN  hProv      -  Handle to the user identifcation
 *               IN  dwKeySpec  -  Specification of the key to retrieve
 *               OUT phUserKey  -  Pointer to key handle of retrieved key
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPGetUserKey)
( HCRYPTPROV hProv,
  DWORD dwKeySpec,
  HCRYPTKEY * phUserKey);
#ifndef LOADLIBRARY
BOOL WINAPI CPGetUserKey
( HCRYPTPROV hProv,
  DWORD dwKeySpec,
  HCRYPTKEY * phUserKey);
#endif
//------------------------------------------------------------------------------
/*
 -	CPImportKey
 -
 *	Purpose:
 *                Import cryptographic keys
 *
 *	Parameters:
 *               IN  hProv     -  Handle to the CSP user
 *               IN  pbData    -  Key blob data
 *               IN  dwDataLen -  Length of the key blob data
 *               IN  hPubKey   -  Handle to the exchange public key value of
 *                                the destination user
 *               IN  dwFlags   -  Flags values
 *               OUT phKey     -  Pointer to the handle to the key which was
 *                                Imported
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPImportKey)
( HCRYPTPROV hProv,
  BYTE * pbData,
  DWORD dwDataLen,
  HCRYPTKEY hImpKey,
  DWORD dwFlags,
  HCRYPTKEY * phKey);
#ifndef LOADLIBRARY
BOOL WINAPI CPImportKey
( HCRYPTPROV hProv,
  BYTE * pbData,
  DWORD dwDataLen,
  HCRYPTKEY hImpKey,
  DWORD dwFlags,
  HCRYPTKEY * phKey);
#endif
//------------------------------------------------------------------------------
/*
 -	CPSetKeyParam
 -
 *	Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a key
 *
 *	Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hKey    -  Handle to a key
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPSetKeyParam)
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  DWORD dwParam,
  BYTE * pbData,
  DWORD dwFlags);
#ifndef LOADLIBRARY
BOOL WINAPI CPSetKeyParam
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  DWORD dwParam,
  BYTE * pbData,
  DWORD dwFlags);
#endif
//==============================================================================
//    Data Encryption Functions
//------------------------------------------------------------------------------
/*
 -	CPDecrypt
 -
 *	Purpose:
 *                Decrypt data
 *
 *	Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of ciphertext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be decrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    decrypted
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPDecrypt)
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  HCRYPTHASH hHash,
  BOOL Final,
  DWORD dwFlags,
  BYTE * pbData,
  DWORD * pdwDataLen);
#ifndef LOADLIBRARY
BOOL WINAPI CPDecrypt
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  HCRYPTHASH hHash,
  BOOL Final,
  DWORD dwFlags,
  BYTE * pbData,
  DWORD * pdwDataLen);
#endif
//------------------------------------------------------------------------------
/*
 -	CPEncrypt
 -
 *	Purpose:
 *                Encrypt data
 *
 *	Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of plaintext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be encrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    encrypted
 *               IN dwBufLen       -  Size of Data buffer
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPEncrypt)
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  HCRYPTHASH hHash,
  BOOL Final,
  DWORD dwFlags,
  BYTE * pbData,
  DWORD * pdwDataLen,
  DWORD dwBufLen);
#ifndef LOADLIBRARY
BOOL WINAPI CPEncrypt
( HCRYPTPROV hProv,
  HCRYPTKEY hKey,
  HCRYPTHASH hHash,
  BOOL Final,
  DWORD dwFlags,
  BYTE * pbData,
  DWORD * pdwDataLen,
  DWORD dwBufLen);
#endif
//==============================================================================
//    Hashing and Digital Signature Functions
//------------------------------------------------------------------------------
/*
 -	CPCreateHash
 -
 *	Purpose:
 *                initate the hashing of a stream of data
 *
 *	Parameters:
 *               IN  hUID    -  Handle to the user identifcation
 *               IN  Algid   -  Algorithm identifier of the hash algorithm
 *                              to be used
 *               IN  hKey    -  Optional key for MAC algorithms
 *               IN  dwFlags -  Flags values
 *               OUT pHash   -  Handle to hash object
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPCreateHash)
( HCRYPTPROV hProv,
  ALG_ID AlgId,
  HCRYPTKEY hKey,
  DWORD dwFlags,
  HCRYPTHASH * phHash);
#ifndef LOADLIBRARY
BOOL WINAPI CPCreateHash
( HCRYPTPROV hProv,
  ALG_ID AlgId,
  HCRYPTKEY hKey,
  DWORD dwFlags,
  HCRYPTHASH * phHash);
#endif
//------------------------------------------------------------------------------
/*
 -	CPDestoryHash
 -
 *	Purpose:
 *                Destory the hash object
 *
 *	Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPDestroyHash)
( HCRYPTPROV hProv,
  HCRYPTHASH hHash);
#ifndef LOADLIBRARY
BOOL WINAPI CPDestroyHash
( HCRYPTPROV hProv,
  HCRYPTHASH hHash);
#endif
//------------------------------------------------------------------------------
/*
 -	CPDuplicateHash
 -
 *	Purpose:
 *                Duplicate Hash
 *
 *	Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hHash      -  Handle to a hash
 *               IN      pdwReserved-  Reserved
 *               IN      dwFlags    -  Flags values
 *               OUT     phHash     -  Handle to a duplicate hash
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPDuplicateHash)
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  DWORD * pdwReserved,
  DWORD dwFlags,
  HCRYPTHASH * phHash);
#ifndef LOADLIBRARY
BOOL WINAPI CPDuplicateHash
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  DWORD * pdwReserved,
  DWORD dwFlags,
  HCRYPTHASH * phHash);
#endif
//------------------------------------------------------------------------------
/*
 -	CPGetHashParam
 -
 *	Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a hash
 *
 *	Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hHash      -  Handle to a hash
 *               IN      dwParam    -  Parameter number
 *               IN      pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPGetHashParam)
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  DWORD dwParam,
  BYTE * pbData,
  DWORD * pdwDataLen,
  DWORD dwFlags);
#ifndef LOADLIBRARY
BOOL WINAPI CPGetHashParam
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  DWORD dwParam,
  BYTE * pbData,
  DWORD * pdwDataLen,
  DWORD dwFlags);
#endif
//------------------------------------------------------------------------------
/*
 -	CPHashData
 -
 *	Purpose:
 *                Compute the cryptograghic hash on a stream of data
 *
 *	Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  pbData    -  Pointer to data to be hashed
 *               IN  dwDataLen -  Length of the data to be hashed
 *               IN  dwFlags   -  Flags values
 *               IN  pdwMaxLen -  Maximum length of the data stream the CSP
 *                                module may handle
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPHashData)
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  BYTE * pbData,
  DWORD dwDataLen,
  DWORD dwFlags);
#ifndef LOADLIBRARY
BOOL WINAPI CPHashData
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  BYTE * pbData,
  DWORD dwDataLen,
  DWORD dwFlags);
#endif
//------------------------------------------------------------------------------
/*
 -	CPHashSessionKey
 -
 *	Purpose:
 *                Compute the cryptograghic hash on a key object.
 *
 *	Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  hKey      -  Handle to a key object
 *               IN  dwFlags   -  Flags values
 *
 *	Returns:
 *               CRYPT_FAILED
 *               CRYPT_SUCCEED
 */
typedef BOOL (WINAPI *D_CPHashSessionKey)
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  HCRYPTKEY hKey,
  DWORD dwFlags);
#ifndef LOADLIBRARY
BOOL WINAPI CPHashSessionKey
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  HCRYPTKEY hKey,
  DWORD dwFlags);
#endif
//------------------------------------------------------------------------------
/*
 -	CPSetHashParam
 -
 *	Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a hash
 *
 *	Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hHash   -  Handle to a hash
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPSetHashParam)
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  DWORD dwParam,
  BYTE * pbData,
  DWORD dwFlags);
#ifndef LOADLIBRARY
BOOL WINAPI CPSetHashParam
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  DWORD dwParam,
  BYTE * pbData,
  DWORD dwFlags);
#endif
//------------------------------------------------------------------------------
/*
 -	CPSignHash
 -
 *	Purpose:
 *                Create a digital signature from a hash
 *
 *	Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  Algid        -  Algorithm identifier of the signature
 *                                   algorithm to be used
 *               IN  sDescription -  Description of data to be signed
 *               IN  dwFlags      -  Flags values
 *               OUT pbSignture   -  Pointer to signature data
 *               OUT dwHashLen    -  Pointer to the len of the signature data
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPSignHash)
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  DWORD dwKeySpec,
  LPCWSTR sDescription,
  DWORD dwFlags,
  BYTE * pbSignature,
  DWORD * pdwSigLen);
#ifndef LOADLIBRARY
BOOL WINAPI CPSignHash
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  DWORD dwKeySpec,
  LPCWSTR sDescription,
  DWORD dwFlags,
  BYTE * pbSignature,
  DWORD * pdwSigLen);
#endif
//------------------------------------------------------------------------------
/*
 -	CPVerifySignature
 -
 *	Purpose:
 *                Used to verify a signature against a hash object
 *
 *	Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  pbSignture   -  Pointer to signature data
 *               IN  dwSigLen     -  Length of the signature data
 *               IN  hPubKey      -  Handle to the public key for verifying
 *                                   the signature
 *               IN  Algid        -  Algorithm identifier of the signature
 *                                   algorithm to be used
 *               IN  sDescription -  Description of data to be signed
 *               IN  dwFlags      -  Flags values
 *
 *	Returns:
 */
typedef BOOL (WINAPI *D_CPVerifySignature)
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  BYTE * pbSignature,
  DWORD dwSigLen,
  HCRYPTKEY hPubKey,
  LPCWSTR sDescription,
  DWORD dwFlags);
#ifndef LOADLIBRARY
BOOL WINAPI CPVerifySignature
( HCRYPTPROV hProv,
  HCRYPTHASH hHash,
  BYTE * pbSignature,
  DWORD dwSigLen,
  HCRYPTKEY hPubKey,
  LPCWSTR sDescription,
  DWORD dwFlags);
#endif
//------------------------------------------------------------------------------
typedef struct _CP_FUNCTION_LIST {
 D_CPAcquireContext CPAcquireContext;
 D_CPGetProvParam CPGetProvParam;
 D_CPReleaseContext CPReleaseContext;
 D_CPSetProvParam CPSetProvParam;
 D_CPDeriveKey CPDeriveKey;
 D_CPDestroyKey CPDestroyKey;
 D_CPDuplicateKey CPDuplicateKey;
 D_CPExportKey CPExportKey;
 D_CPGenKey CPGenKey;
 D_CPGenRandom CPGenRandom;
 D_CPGetKeyParam CPGetKeyParam;
 D_CPGetUserKey CPGetUserKey;
 D_CPImportKey CPImportKey;
 D_CPSetKeyParam CPSetKeyParam;
 D_CPDecrypt CPDecrypt;
 D_CPEncrypt CPEncrypt;
 D_CPCreateHash CPCreateHash;
 D_CPDestroyHash CPDestroyHash;
 D_CPDuplicateHash CPDuplicateHash;
 D_CPGetHashParam CPGetHashParam;
 D_CPHashData CPHashData;
 D_CPHashSessionKey CPHashSessionKey;
 D_CPSetHashParam CPSetHashParam;
 D_CPSignHash CPSignHash;
 D_CPVerifySignature CPVerifySignature;
} CP_FUNCTION_LIST;
//------------------------------------------------------------------------------
typedef BOOL (WINAPI *D_CPGetFunctionList)
( CP_FUNCTION_LIST **ppFunctionList );
#ifndef LOADLIBRARY
BOOL WINAPI CPGetFunctionList
( CP_FUNCTION_LIST **ppFunctionList );
#endif
//------------------------------------------------------------------------------
#ifdef  __cplusplus
}
#endif
//------------------------------------------------------------------------------
#endif

