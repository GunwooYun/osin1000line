#include "user.h"

extern char __stack_top[]; // Linker script

int syscall(int sysno, int arg0, int arg1, int arg2)
{
    // 변수를 각 register 와 연결
    register int a0 __asm__("a0") = arg0;
    register int a1 __asm__("a1") = arg1;
    register int a2 __asm__("a2") = arg2;
    register int a3 __asm__("a3") = sysno;

    // ecall 명령어: 커널로 처리를 위임
    // 예외 핸들러가 호출되어 제어권이 커널로 넘어감
    __asm__ __volatile__ ("ecall"
                            : "=r"(a0)
                            : "r"(a0), "r"(a1), "r"(a2), "r"(a3)
                            : "memory");
    return a0; // 커널에서 반환하는 값은 a0 레지스터에 저장
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

// application을 종료
__attribute__((noreturn)) void exit(void){
    syscall(SYS_EXIT, 0, 0, 0);
    for(;;);
}

void putchar(char ch)
{
    syscall(SYS_PUTCHAR, ch, 0, 0);
}

int getchar(void)
{
    return syscall(SYS_GETCHAR, 0, 0, 0);
}
