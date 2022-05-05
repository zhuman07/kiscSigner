//------------------------------------------------------------------------------
// ALL Projects
// Copyright (c) 2010 Scientific Lab. Gamma Technologies. All rights reserved.
//------------------------------------------------------------------------------
#ifndef __TDEFS_H
#define __TDEFS_H
//------------------------------------------------------------------------------
#undef LINUX32
#undef LINUX64
#undef LINUXXX
#undef DEC64
#undef WIND32
#undef WIND64
#undef WINDXX
#undef SPARC32
#undef SPARC64
#undef SPARCXX
#undef AIX32
#undef AIX64
#undef AIXXX
#undef HP32
#undef HP64
#undef HPXX
#undef SUN386
#undef MAC32
#undef MAC64
#undef MACXX
#undef ARM32
//------------------------------------------------------------------------------
#if defined(WIN32) || defined(__WIN32__)
#if !defined(_WIN32)
#define _WIN32
#endif
#endif
//
#if defined(WIN64) || defined(__WIN64__)
#if !defined(_WIN64)
#define _WIN64
#endif
#endif
//------------------------------------------------------------------------------
#if defined(__ARMEL__)
  #define ARM32
#elif defined(__gnu_linux__) || defined(__linux__)
  #define LINUXXX
  #if defined(__x86_64__) || defined(__x86_64) || defined(__amd64__)
    #define LINUX64
  #else
    #define LINUX32
  #endif
#elif defined(_WIN32) || defined(_WIN64)
  #define WIND32
  #define WINDXX
  #ifdef _WIN64
    #define WIND64
  #endif
#elif defined(__alpha) && defined(__arch64__)
  #define DEC64
//#elif (__ARM_ARCH__ > 3) || defined(__ARM_ARCH_3M__)) && !defined(__ARM_ARCH_6M__)
//#elif defined(__ARM_EABI__)
//#elif defined(__AVR__)
//#elif defined(__MAVERICK__)
#elif defined(__APPLE__) && defined(__MACH__) // Mac OS X (client) 10.x (or server 1.x/10.x) - gcc or Metrowerks MachO compilers
  #define MACXX
  #ifdef FORCE32
    #define MAC32
  #else
    #define MAC64
  #endif
#elif  defined(__sun) ||  defined(__sun__)
  #define SPARCXX
  #ifdef FORCE32
    #define SPARC32
  #else
    #define SPARC64
  #endif
#ifndef __sparc__ // __i386__
#define SUN386
#endif
#elif _AIX
  #define AIXXX
  #ifdef FORCE32
    #define AIX32
  #else
    #define AIX64
  #endif 
#else // __hpux
  #define HPXX
  #ifdef FORCE32
    #define HP32
  #else
    #define HP64
  #endif
#endif 
//------------------------------------------------------------------------------
#ifdef WINDXX
  #ifndef _MT
    #define _MT  
  #endif
//  #include <windows.h>
  #define SLASH '\\'
#else
  #ifdef PTHREAD
    #include <pthread.h>
  #endif
  #define SLASH '/'
#endif
//------------------------------------------------------------------------------
#if defined DEC64
  #define _BSD
#endif
//------------------------------------------------------------------------------
#if defined WINDXX
  #define RANG32
  #define INVERT
  #ifdef _MSC_VER
  typedef __int64           long64;
  typedef unsigned __int64 ulong64;
  #else
  typedef long long           long64;
  typedef unsigned long long ulong64;
  #endif
#elif   defined   LINUX32
  #define RANG32
  #define INVERT
  typedef long long           long64;
  typedef unsigned long long ulong64;
#elif   defined   LINUX64
  #define RANG64
  #define INVERT
  typedef long           long64;
  typedef unsigned long ulong64;
#elif   defined   DEC64
  #define RANG64
  #define INVERT
  typedef long           long64;
  typedef unsigned long ulong64;
#elif   defined   MAC32
  #define RANG32
  #define INVERT
  typedef long long           long64;
  typedef unsigned long long ulong64;
#elif   defined   MAC64
  #define RANG64
  #define INVERT
  typedef long           long64;
  typedef unsigned long ulong64;
#elif   defined   ARM32
  #define RANG32
  #define INVERT
  typedef long long           long64;
  typedef unsigned long long ulong64;
#elif   defined   SPARC32
  #define RANG32
  #ifdef SUN386
    #define INVERT
  #else
    #define DIRECT
  #endif
  typedef long long           long64;
  typedef unsigned long long ulong64;
#elif   defined   SPARC64
  #define RANG64
  #ifdef SUN386
    #define INVERT
  #else
    #define DIRECT
  #endif
  typedef long           long64;
  typedef unsigned long ulong64;
#elif   defined   HP32
  #define RANG32
  #define DIRECT
  typedef long long           long64;
  typedef unsigned long long ulong64;
#elif   defined   HP64
  #define RANG64
  #define DIRECT
  typedef long           long64;
  typedef unsigned long ulong64;
#elif   defined   AIX32
  #define RANG32
  #define DIRECT
  typedef long long           long64;
  typedef unsigned long long ulong64;
#elif   defined   AIX64
  #define RANG64
  #define DIRECT
  typedef long           long64;
  typedef unsigned long ulong64;
#endif
//------------------------------------------------------------------------------
#if defined(RANG32) && !defined(WIND64)
  typedef long           long32;
  typedef unsigned long ulong32;
#else
  typedef int            long32;
  typedef unsigned int  ulong32;
#endif
  typedef unsigned short int UINT2;
  typedef unsigned int       UINT4;
  //typedef ulong64            UINT8;
//------------------------------------------------------------------------------

#ifndef POINTER
typedef unsigned char *       POINTER;
#endif
#ifndef NULL_PTR
#define NULL_PTR ((POINTER)0)
#endif

#ifndef INADDR_NONE
#ifdef HPXX
#define INADDR_NONE             ((in_addr_t)0xffffffff) /* -1 return */
#else
#define INADDR_NONE 0xffffffff
#endif
#endif

#if defined INVERT
  #define I0 0
  #define I1 1
  #define C0 0
  #define C1 1
  #define C2 2
  #define C3 3
#elif defined DIRECT
  #define I0 1
  #define I1 0
  #define C0 3
  #define C1 2
  #define C2 1
  #define C3 0
#endif
//------------------------------------------------------------------------------
#ifndef drct_i
#define drct_i(i) i=((i>>8)|(i<<8))
#endif
#ifndef drct_l
#define drct_l(l) l=(((l<<24)|(l>>8))&0xFF00FF00)|(((l<<8)|(l>>24))&0x00FF00FF)
#endif
//------------------------------------------------------------------------------
#if defined WINDXX
  // ����������� ���� unix ����
  typedef     int       pid_t;
  // ���������� ���� run time libc � unix ����
  // �������
  #define     getpid    _getpid
  #define     mkdir     _mkdir
  #define     open      _open
  #define     creat     _creat
  //#define     close     _close
  #define     write     _write
  #define     read      _read
  #define     unlink    _unlink
  #define     chmod     _chmod
  #define     utime     _utime
  #define     itoa      _itoa
#if defined(_MSC_VER) && !defined(_WIN64)
  #define     vsnprintf _vsnprintf
#endif
  // �����
  #define     O_CREAT   _O_CREAT
  #define     O_RDWR    _O_RDWR
  #define     O_EXCL    _O_EXCL
  #define     O_WRONLY  _O_WRONLY
  #define     O_TRUNC   _O_TRUNC
  #define     S_IREAD   _S_IREAD
  #define     S_IWRITE  _S_IWRITE
  #if defined WIND64
    #define _CRT_SECURE_NO_WARNINGS
    #define   strdup    _strdup
  #endif
#endif
//------------------------------------------------------------------------------
#endif
