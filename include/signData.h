#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#ifdef WIND32
#include <windows.h>
#endif
#include "loadTcsp.h"

namespace kiscSigner{
DWORD GetLastErrorCSP(HCRYPTPROV hProv);
int signData(std::string *profile, std::string *data, std::string *sign);
int verify(char *profile, unsigned char *data, unsigned char *sign);
};
