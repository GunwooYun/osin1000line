#ifndef __KERNEL_H__
#define __KERNEL_H__

#include "common.h"

// 애플리케이션 이미지의 기본 가상 주소, user.ld 정의된 시작 주소와 일치
#define USER_BASE 0x1000000

// U-Mode 로 진입할 때 하드웨어 인터럽트 활성화, stvec 레지스터에 설정된 핸들러 호출
#define SSTATUS_SPIE (1 << 5)

#define SCAUSE_ECALL    8
#define PROC_EXITED     2

extern char __kernel_base[];    // linker script 변수

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

#define SATP_SV32 (1u << 31) // satp 레지스터에서 "Sv32 모드 페이지 활성화" 비트
#define PAGE_V    (1 << 0)   // "Valid" 비트 (엔트리가 유효함을 의미)
#define PAGE_R    (1 << 1)   // 읽기 가능
#define PAGE_W    (1 << 2)   // 쓰기 가능
#define PAGE_X    (1 << 3)   // 실행 가능
#define PAGE_U    (1 << 4)   // 사용자 모드 접근 가능

struct process {
    int pid;             // 프로세스 ID
    int state;           // 프로세스 상태: PROC_UNUSED 또는 PROC_RUNNABLE
    vaddr_t sp;          // 스택 포인터
    uint32_t *page_table;
    uint8_t stack[8192]; // 커널 스택
};

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
