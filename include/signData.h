#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#ifdef WIND32
#include <windows.h>
#endif
#include "loadTcsp.h"

namespace kiscSigner{
DWORD GetLastErrorCSP(HCRYPTPROV hProv);
int signData(std::string *profile, std::string *data, unsigned char *sign);
int verify(std::string *profile, std::string *data, unsigned char *sign);
};
