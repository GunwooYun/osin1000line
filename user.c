#include "user.h"

extern char __stack_top[]; // Linker script

// application을 종료
__attribute__((noreturn)) void exit(void){
    for(;;);
}

void putchar(char c)
{
    /* TODO */
}


__attribute__((section(".text.start")))
__attribute__((naked))
void start(void)
{
    __asm__ __volatile__(
        "mv sp, %[stack_top] \n" // stack 포인터 설정
        "call main          \n" // main 함수 호출
        "call exit          \n"
        :: [stack_top] "r" (__stack_top)
    );
}
