#include "common.h"

void putchar(char ch);
#if 0
void putchar(char ch){
	sbi_call(ch, 0, 0, 0, 0, 0, 0, 1 /* Console Putchar */);
}
#endif

void printf(const char* fmt, ...)
{
    va_list vargs;
    /* 컴파일러는 고정 인자인 fmt가 끝나는 바로 다음 지점의 주소를 계산해서 vargs 라는 포인터 변수에 저장, fmt를 파라메터로 넣는 이유는 fmt가 끝나는 지점부터 가변 인자 목록의 시작점이기 때문 */
    va_start(vargs, fmt);

    while(*fmt)
    {
        if(*fmt == '%') // 문자열에 %가 있으면 분기 처리
        {
            fmt++; // skip '%'
            switch(*fmt)
            {
                case '\0': // null pointer
                {
                    putchar('%');
                    goto end;
                }
                case '%': // % 문자
                {
                    putchar('%');
                    break;
                }
                case 's': // %s 문자열
                {
                    const char *s = va_arg(vargs, const char *);
                    while(*s)
                    {
                        putchar(*s);
                        s++;
                    }
                    break;
                }
                case 'd': // %d 10진수
                {
                    int value = va_arg(vargs, int);
                    unsigned magnitude = value;
                    if(value < 0) // 음수일 경우, '-' 출력 후, 양수 처리
                    {
                        putchar('-');
                        magnitude = -magnitude;
                    }

                    /* 자리수 계산, 예: 277일 경우, divisor 는 100 */
                    unsigned divisor = 1;
                    while(magnitude / divisor > 9)
                    {
                        divisor *= 10;
                    }

                    while(divisor > 0)
                    {
                        putchar ('0' + magnitude / divisor); // ascii 코드로 변환 후 출력
                        magnitude %= divisor; // 아래 자리 구하기 (예: 277이면 77)
                        divisor /= 10; // divisor 자리수 줄이기
                    }
                    break;
                }
                case 'x': // %x 16진수
                {
                    // 가변 인자 목록에서 4bytes 부호 없는 정수를 가져옴
                    unsigned value = va_arg(vargs, unsigned);
                    for(int i = 7; i >= 0; i--)
                    {
                        unsigned nibble = (value >> (i * 4)) & 0xf; // 32bit 값을 4bit씩 8번 반복 마스킹
                        putchar("0123456789abcdef"[nibble]); // 대박, 문자열이 곧 배열, [nibble]은 인덱스
                    }
                }
            }
        }
        else
        {
            putchar(*fmt); // 1byte 씩 출력
        }

        fmt++;
    }

end:
    va_end(vargs);
}


void *memset(void *buf, char c, size_t n){
	uint8_t *p = (uint8_t *) buf;

	while(n--){
		*p++ = c;
	}
	return buf;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while(n--)
    {
        *d++ = *s++;
    }

    return dst;
}

char *strcpy(char *dst, const char *src)
{
    char *d = dst;
    while (*src)
    {
        *d++ = *src++;
    }
    *d = '\0';

    return dst;
}

int strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2)
    {
        if (*s1 != *s2)
        {
            break;
        }
        s1++;
        s2++;
    }

    return *(unsigned char *)s1 - *(unsigned char *)s2; // unsigned char for POSIX
}
