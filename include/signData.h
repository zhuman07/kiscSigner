#include <stdlib.h>
#include <stdio.h>
#ifdef WIND32
#include <windows.h>
#endif
#include "loadTcsp.h"

namespace kiscSigner{
DWORD GetLastErrorCSP(HCRYPTPROV hProv);
int signData(char *profile, unsigned char *data, unsigned char *sign);
int verify(char *profile, unsigned char *data, unsigned char *sign);
};
