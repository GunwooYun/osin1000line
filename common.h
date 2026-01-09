#ifndef __COMMON_H__
#define __COMMON_H__

typedef int bool;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef uint32_t size_t;

typedef uint32_t paddr_t; // 물리 메모리 주소
typedef uint32_t vaddr_t; // 가상 메모리 주소

#define true 1
#define false 0

#define NULL ((void *)0)

/* system call */
#define SYS_PUTCHAR     1
#define SYS_GETCHAR     2
#define SYS_EXIT        3
#define SYS_READFILE    4
#define SYS_WRITEFILE   5

/*
value를 align 배수로 맞춰 올림
여기서 align은 2의 거듭제급이어야 함
예) aligned_up(0x1234, 0x1000) 는 0x2000 반환 */
#define align_up(value, align)  __builtin_align_up(value, align)
/*
value가 2의 배수인지 확인,
align은 2의 거듭제곱이어야 함
예) is_aligned(0x2000, 0x1000) 이면 true, is_aligned(0x2f00, 0x1000) 이면 flase */
#define is_aligned(value, align)  __builtin_is_aligned(value, align)
/*
구조체 내에서 특정 멤버가 시작되는 위치(바이트 단위)를 반환
*/
#define offsetof(type, member)  __builtin_offsetof(type, member)

#define va_list     __builtin_va_list   //가변 인자들의 목록을 가리키는 포인터 타입
#define va_start    __builtin_va_start  // 가변 인자를 읽기 시작할 위치를 초기화
#define va_end      __builtin_va_end    // 목록에서 특정 타입(int, char *등) 만큼 데이터를 읽어서 가져옴
#define va_arg      __builtin_va_arg    // 인자 읽기가 끝났음을 알리고 정리

/*
__builtin_ 매크로는 컴파일러 clang에서 내부적으로 미리 구현해 놓은 기능을 호출
표준라이브러리가 없는 커널에서는 (예: stdio.h, stdlib.h 등) 컴파일러의 내장 기능을 빌려 씀
컴파일러는 각 CPU 아키텍처에 맞게 인자들이 레지스터나 스택에 어떻게 배치되는지 잘 알기 때문에,
이 방식이 가장 안전하고 확실

컴파일러가 __builtin_ 매크로를 만나면, 별도의 외부 라이브러리 함수를 찾지 않고 해당 CPU의
호출 규약에 맞춰서 최적화된 기계어를 직접 생성한다.

*/

void* memset(void *buf, char c, size_t n);
void *memcpy(void *dst, const void *src, size_t n);
char *strcpy(char *dst, const char *src);
int strcmp(const char *s1, const char *s2);

//void putchar(char ch);
/*
const char *fmt는 첫번째 인자로 출력 형식을 담을 문자열을 받는다.
그리고 ...은 뒤에 몇개의 인자가 올지 모르고, 다양한 타입도 받을 수 있다고 컴파일러에게 알린다.
*/
void printf(const char *fmt, ...);

#endif
