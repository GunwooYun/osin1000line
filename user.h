#ifndef __USER_H__
#define __USER_H__

#include "common.h"
__attribute__((noreturn)) void exit(void);
void putchar(char ch);
int getchar(void);
// filesystem
int readfile(const char *filename, char *buf, int len);
int writefile(const char *filename, const char *buf, int len);
#endif

