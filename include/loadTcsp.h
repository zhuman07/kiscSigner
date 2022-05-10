//------------------------------------------------------------------------------
// Tumar CSP Project
// Copyright (c) 2008 Scientific Lab. Gamma Technologies. All rights reserved.
//
// TCSP Loader
//------------------------------------------------------------------------------
//#include "tdefs.h"
#include <stdio.h>
#include <string.h>
#ifdef WIND32
#include <windows.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include "wdefs.h"
#endif

#ifndef LOAD_TCSP_H
#define LOAD_TCSP_H
//------------------------------------------------------------------------------
#include "tdefs.h"
//------------------------------------------------------------------------------
#define LOADLIBRARY
#include "cptumar.h"
//------------------------------------------------------------------------------
#ifndef ER_LOAD_CPAcquireContext
#define ER_LOAD_CPAcquireContext   1
#define ER_LOAD_CPGetProvParam     2
#define ER_LOAD_CPReleaseContext   3
#define ER_LOAD_CPSetProvParam     4
#define ER_LOAD_CPDeriveKey        5
#define ER_LOAD_CPDestroyKey       6
#define ER_LOAD_CPDuplicateKey     7
#define ER_LOAD_CPExportKey        8
#define ER_LOAD_CPGenKey           9
#define ER_LOAD_CPGenRandom       10
#define ER_LOAD_CPGetKeyParam     11
#define ER_LOAD_CPGetUserKey      12
#define ER_LOAD_CPImportKey       13
#define ER_LOAD_CPSetKeyParam     14
#define ER_LOAD_CPDecrypt         15
#define ER_LOAD_CPEncrypt         16
#define ER_LOAD_CPCreateHash      17
#define ER_LOAD_CPDestroyHash     18
#define ER_LOAD_CPDuplicateHash   19
#define ER_LOAD_CPGetHashParam    20
#define ER_LOAD_CPHashData        21
#define ER_LOAD_CPHashSessionKey  22
#define ER_LOAD_CPSetHashParam    23
#define ER_LOAD_CPSignHash        24
#define ER_LOAD_CPVerifySignature 25
//------------------------------------------------------------------------------
#endif
//------------------------------------------------------------------------------
int  LoadTumarCSP(char *lib_path); // if lib_path is NULL - use default path
void FreeTumarCSP(void);
int  GetTcspPath(char *path);
//------------------------------------------------------------------------------
extern D_CPAcquireContext  CPAcquireContext;
extern D_CPGetProvParam    CPGetProvParam;
extern D_CPReleaseContext  CPReleaseContext;
extern D_CPSetProvParam    CPSetProvParam;
extern D_CPDeriveKey       CPDeriveKey;
extern D_CPDestroyKey      CPDestroyKey;
extern D_CPDuplicateKey    CPDuplicateKey;
extern D_CPExportKey       CPExportKey;
extern D_CPGenKey          CPGenKey;
extern D_CPGenRandom       CPGenRandom;
extern D_CPGetKeyParam     CPGetKeyParam;
extern D_CPGetUserKey      CPGetUserKey;
extern D_CPImportKey       CPImportKey;
extern D_CPSetKeyParam     CPSetKeyParam;
extern D_CPDecrypt         CPDecrypt;
extern D_CPEncrypt         CPEncrypt;
extern D_CPCreateHash      CPCreateHash;
extern D_CPDestroyHash     CPDestroyHash;
extern D_CPDuplicateHash   CPDuplicateHash;
extern D_CPGetHashParam    CPGetHashParam;
extern D_CPHashData        CPHashData;
extern D_CPHashSessionKey  CPHashSessionKey;
extern D_CPSetHashParam    CPSetHashParam;
extern D_CPSignHash        CPSignHash;
extern D_CPVerifySignature CPVerifySignature;
//------------------------------------------------------------------------------
#ifdef WIND32
#define CSP_REGKEY "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Tumar CSP"
#define CSP_VALUE  "Image Path"
#else
#ifdef PTHREAD
#define CSP_LIB_PATH CSP_LIB_LINK_R
#else
#define CSP_LIB_PATH CSP_LIB_LINK
#endif
#endif
//------------------------------------------------------------------------------
#endif


