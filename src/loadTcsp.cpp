//------------------------------------------------------------------------------
// Tumar CSP Project
// Copyright (c) 2008 Scientific Lab. Gamma Technologies. All rights reserved.
//
// TCSP Loader
//------------------------------------------------------------------------------
#include "tdefs.h"
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

#include "loadTcsp.h"
//------------------------------------------------------------------------------
#ifndef WIND32
#define LoadLibrary(x)      dlopen(x,RTLD_LAZY)
#define GetProcAddress(x,y) dlsym(x,y)
#define FreeLibrary(x)      dlclose(x)
#endif
//------------------------------------------------------------------------------
D_CPAcquireContext  CPAcquireContext;
D_CPGetProvParam    CPGetProvParam;
D_CPReleaseContext  CPReleaseContext;
D_CPSetProvParam    CPSetProvParam;
D_CPDeriveKey       CPDeriveKey;
D_CPDestroyKey      CPDestroyKey;
D_CPDuplicateKey    CPDuplicateKey;
D_CPExportKey       CPExportKey;
D_CPGenKey          CPGenKey;
D_CPGenRandom       CPGenRandom;
D_CPGetKeyParam     CPGetKeyParam;
D_CPGetUserKey      CPGetUserKey;
D_CPImportKey       CPImportKey;
D_CPSetKeyParam     CPSetKeyParam;
D_CPDecrypt         CPDecrypt;
D_CPEncrypt         CPEncrypt;
D_CPCreateHash      CPCreateHash;
D_CPDestroyHash     CPDestroyHash;
D_CPDuplicateHash   CPDuplicateHash;
D_CPGetHashParam    CPGetHashParam;
D_CPHashData        CPHashData;
D_CPHashSessionKey  CPHashSessionKey;
D_CPSetHashParam    CPSetHashParam;
D_CPSignHash        CPSignHash;
D_CPVerifySignature CPVerifySignature;
//------------------------------------------------------------------------------
HINSTANCE hTcspLib=NULL;
//------------------------------------------------------------------------------
#ifdef WIND32
class _csp_lock_sec{
public:
  _csp_lock_sec(void){InitializeCriticalSection(&hCS);}
 ~_csp_lock_sec(void){DeleteCriticalSection    (&hCS);}
  void enter(void)   {EnterCriticalSection     (&hCS);}
  void leave(void)   {LeaveCriticalSection     (&hCS);}
private:
  CRITICAL_SECTION hCS;
} csp_xlock;
#else
class _csp_lock_sec{
public:
  _csp_lock_sec(void){}
 ~_csp_lock_sec(void){}
  void enter(void)   {}
  void leave(void)   {}
} csp_xlock;
#endif
//------------------------------------------------------------------------------
int GetTcspFancs(HINSTANCE hLib)
{
 if ((CPAcquireContext =(D_CPAcquireContext)  GetProcAddress(hLib,"CPAcquireContext")) ==NULL) return ER_LOAD_CPAcquireContext;
 if ((CPGetProvParam   =(D_CPGetProvParam)    GetProcAddress(hLib,"CPGetProvParam"))   ==NULL) return ER_LOAD_CPGetProvParam;
 if ((CPReleaseContext =(D_CPReleaseContext)  GetProcAddress(hLib,"CPReleaseContext")) ==NULL) return ER_LOAD_CPReleaseContext;
 if ((CPSetProvParam   =(D_CPSetProvParam)    GetProcAddress(hLib,"CPSetProvParam"))   ==NULL) return ER_LOAD_CPSetProvParam;
 if ((CPDeriveKey      =(D_CPDeriveKey)       GetProcAddress(hLib,"CPDeriveKey"))      ==NULL) return ER_LOAD_CPDeriveKey;
 if ((CPDestroyKey     =(D_CPDestroyKey)      GetProcAddress(hLib,"CPDestroyKey"))     ==NULL) return ER_LOAD_CPDestroyKey;
 if ((CPDuplicateKey   =(D_CPDuplicateKey)    GetProcAddress(hLib,"CPDuplicateKey"))   ==NULL) return ER_LOAD_CPDuplicateKey;
 if ((CPExportKey      =(D_CPExportKey)       GetProcAddress(hLib,"CPExportKey"))      ==NULL) return ER_LOAD_CPExportKey;
 if ((CPGenKey         =(D_CPGenKey)          GetProcAddress(hLib,"CPGenKey"))         ==NULL) return ER_LOAD_CPGenKey;
 if ((CPGenRandom      =(D_CPGenRandom)       GetProcAddress(hLib,"CPGenRandom"))      ==NULL) return ER_LOAD_CPGenRandom;
 if ((CPGetKeyParam    =(D_CPGetKeyParam)     GetProcAddress(hLib,"CPGetKeyParam"))    ==NULL) return ER_LOAD_CPGetKeyParam;
 if ((CPGetUserKey     =(D_CPGetUserKey)      GetProcAddress(hLib,"CPGetUserKey"))     ==NULL) return ER_LOAD_CPGetUserKey;
 if ((CPImportKey      =(D_CPImportKey)       GetProcAddress(hLib,"CPImportKey"))      ==NULL) return ER_LOAD_CPImportKey;
 if ((CPSetKeyParam    =(D_CPSetKeyParam)     GetProcAddress(hLib,"CPSetKeyParam"))    ==NULL) return ER_LOAD_CPSetKeyParam;
 if ((CPDecrypt        =(D_CPDecrypt)         GetProcAddress(hLib,"CPDecrypt"))        ==NULL) return ER_LOAD_CPDecrypt;
 if ((CPEncrypt        =(D_CPEncrypt)         GetProcAddress(hLib,"CPEncrypt"))        ==NULL) return ER_LOAD_CPEncrypt;
 if ((CPCreateHash     =(D_CPCreateHash)      GetProcAddress(hLib,"CPCreateHash"))     ==NULL) return ER_LOAD_CPCreateHash;
 if ((CPDestroyHash    =(D_CPDestroyHash)     GetProcAddress(hLib,"CPDestroyHash"))    ==NULL) return ER_LOAD_CPDestroyHash;
 if ((CPDuplicateHash  =(D_CPDuplicateHash)   GetProcAddress(hLib,"CPDuplicateHash"))  ==NULL) return ER_LOAD_CPDuplicateHash;
 if ((CPGetHashParam   =(D_CPGetHashParam)    GetProcAddress(hLib,"CPGetHashParam"))   ==NULL) return ER_LOAD_CPGetHashParam;
 if ((CPHashData       =(D_CPHashData)        GetProcAddress(hLib,"CPHashData"))       ==NULL) return ER_LOAD_CPHashData;
 if ((CPHashSessionKey =(D_CPHashSessionKey)  GetProcAddress(hLib,"CPHashSessionKey")) ==NULL) return ER_LOAD_CPHashSessionKey;
 if ((CPSetHashParam   =(D_CPSetHashParam)    GetProcAddress(hLib,"CPSetHashParam"))   ==NULL) return ER_LOAD_CPSetHashParam;
 if ((CPSignHash       =(D_CPSignHash)        GetProcAddress(hLib,"CPSignHash"))       ==NULL) return ER_LOAD_CPSignHash;
 if ((CPVerifySignature=(D_CPVerifySignature) GetProcAddress(hLib,"CPVerifySignature"))==NULL) return ER_LOAD_CPVerifySignature;
 return 0;
}
//------------------------------------------------------------------------------
int GetTcspPath(char *path)
{
#ifdef WIND32
 HKEY hKey;
 DWORD Disposition,DataSize;
 REGSAM samDesired[3]={KEY_READ,KEY_READ|KEY_WOW64_32KEY,KEY_READ|KEY_WOW64_64KEY};
 int j;
 path[0]=0;
 for(j=0;j<3;j++) {
   if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,CSP_REGKEY,0,samDesired[j],&hKey)!=ERROR_SUCCESS) continue;
   DataSize=255;  if (RegQueryValueExA(hKey,CSP_VALUE,0,&Disposition,(BYTE *)path,&DataSize)!=ERROR_SUCCESS) {RegCloseKey(hKey); continue;}
   RegCloseKey(hKey);
   break;
 }
 if (!path[0]) return 1;
#else
 strcpy(path,CSP_LIB_PATH);
#endif
 return 0;
}
//------------------------------------------------------------------------------
int LoadTumarCSP(char *lib_path)
{
 int code;
 char path[260];
 csp_xlock.enter();
 if (hTcspLib)               {csp_xlock.leave(); return 0;}
 if ((lib_path)&&(*lib_path)) strcpy_s(path,lib_path);
 else if (GetTcspPath(path)) {csp_xlock.leave(); return -1;}
 hTcspLib=LoadLibraryA(path);
 if (!hTcspLib)              {csp_xlock.leave(); return -2;}
 code=GetTcspFancs(hTcspLib);
 if (code) {FreeLibrary(hTcspLib); hTcspLib=NULL;}
 csp_xlock.leave();
 return code;
}
//------------------------------------------------------------------------------
void FreeTumarCSP(void)
{
 if (hTcspLib) {FreeLibrary(hTcspLib); hTcspLib=NULL;}
}
//------------------------------------------------------------------------------


