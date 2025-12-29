#ifndef __KERNEL_H__
#define __KERNEL_H__

#include "common.h"

/*
do-while(0) 으로 감싸는 이유는 매크로 전체를 하나의 실행 단위로 만들어주기 때문이다.
그래서 세미콜론과 같은 문제를 해결해 줄 수 있다.
만약 아래와 같이 조건문을 사용하면 컴파일 에러가 발생할 수 있다.
if (condition)
    PANIC("error!"); // 여기서 컴파일 에러 발생 가능성 높음
else
    do_something();

*/

/*
##__VA_ARGS__ 는 PANIC 함수를 사용할 때, ... (가변 인자)가 없을 경우에도 컴파일 에러 없이
진행시켜준다. 즉, PANIC("error!!") 가 사용 가능하다.
*/
#define PANIC(fmt, ...)                                                        \
    do {                                                                       \
        printf("PANIC: %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__);  \
        while (1) {}                                                           \
    } while (0)

#define PAGE_SIZE 4096

struct sbiret{
	long error;
	long value;
};

struct trap_frame
{
    /* Return Address */
    uint32_t ra;
    /* Global Pointer */
    uint32_t gp;
    /* Thread Pointer */
    uint32_t tp;
    /* Temporaries */
    uint32_t t0;
    uint32_t t1;
    uint32_t t2;
    uint32_t t3;
    uint32_t t4;
    uint32_t t5;
    uint32_t t6;
    /* Arguments */
    uint32_t a0;
    uint32_t a1;
    uint32_t a2;
    uint32_t a3;
    uint32_t a4;
    uint32_t a5;
    uint32_t a6;
    uint32_t a7;
    /* Saved */
    uint32_t s0;
    uint32_t s1;
    uint32_t s2;
    uint32_t s3;
    uint32_t s4;
    uint32_t s5;
    uint32_t s6;
    uint32_t s7;
    uint32_t s8;
    uint32_t s9;
    uint32_t s10;
    uint32_t s11;
    /**/
    uint32_t sp;
} __attribute__((packed));

/*
Control and Status Register Read (csrr) 명령어를 이용해 데이터read 
GCC의 확장 문법. 여러 줄의 실행 문장을 중괄호로 묶고,
마지막에 적힌 변수(__tmp)의 값을 마치 함수의 반환값처럼 돌려주는 기능
*/
#define READ_CSR(reg)                                                          \
    ({                                                                         \
        unsigned long __tmp;                                                   \
        __asm__ __volatile__("csrr %0, " #reg : "=r"(__tmp));                  \
        __tmp;                                                                 \
    })

/*
Control and Status Register Write (csrw) 명령어를 이용해 데이터 write
*/
#define WRITE_CSR(reg, value)                                                  \
    do {                                                                       \
        uint32_t __tmp = (value);                                              \
        __asm__ __volatile__("csrw " #reg ", %0" ::"r"(__tmp));                \
    } while (0)

#endif
