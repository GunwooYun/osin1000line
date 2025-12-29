#include "kernel.h"
#include "common.h"


void kernel_entry(void);

extern char __bss[], __bss_end[], __stack_top[];
extern char __free_ram[], __free_ram_end[]; // 메모리 할당 영역

struct sbiret sbi_call(long arg0,long arg1, long arg2, long arg3, long arg4,
						long arg5, long fid, long eid){

	register long a0 __asm__("a0") = arg0;
	register long a1 __asm__("a1") = arg1;
	register long a2 __asm__("a2") = arg2;
	register long a3 __asm__("a3") = arg3;
	register long a4 __asm__("a4") = arg4;
	register long a5 __asm__("a5") = arg5;
	register long a6 __asm__("a6") = fid;
	register long a7 __asm__("a7") = eid;


	__asm__ __volatile__ ("ecall"
							: "=r"(a0), "=r"(a1)
							: "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5),
							  "r"(a6), "r"(a7)
							: "memory");

	return (struct sbiret){.error = a0, .value = a1};
}

void putchar(char ch){
	sbi_call(ch, 0, 0, 0, 0, 0, 0, 1 /* Console Putchar */);
}


paddr_t alloc_pages(uint32_t n)
{
    static paddr_t next_paddr = (paddr_t)__free_ram;
    paddr_t paddr = next_paddr; // 할당 시작 주소
    next_paddr += n * PAGE_SIZE; // n * 페이지 사이즈만큼 할당

    if(next_paddr > (paddr_t)__free_ram_end)
    {
        PANIC("Out of memory");
    }

    memset((void *)paddr, 0x00, n * PAGE_SIZE);

    return paddr;
}

void kernel_main(void){
	memset(__bss, 0x00, (size_t)__bss_end - (size_t)__bss);

    /*
	const char *s = "\r\n\nHello World!\r\n";
	for (int i = 0; s[i] != '\0'; i++){
		putchar(s[i]);
	}
    */

    /* stvec
    Supervisor Trap Vector: S-Mode에서 트랩(예외/인터럽트)이 발생했을 때 점프할 기본 주소를 담은 레지스터 */
    //WRITE_CSR(stvec, (uint32_t) kernel_entry);
    //__asm__ __volatile__("unimp");

    paddr_t paddr0 = alloc_pages(2);
    paddr_t paddr1 = alloc_pages(1);

    printf("free_ram=%x\n", __free_ram);
    printf("alloc_pages test: paddr0=%x\n", paddr0);
    printf("alloc_pages test: paddr1=%x\n", paddr1);

    PANIC("booted!");
    printf("Never reach here\r\n");

    printf("\n\nHello %s\n", "World!");
    printf("1 + 2 = %d, %x\n", 1 + 2, 0x1234abcd);

	//while(1);
	for(;;){
		__asm__ volatile("wfi");
	}
}

__attribute__((section(".text.boot")))
__attribute__((naked))
void boot(void){
	__asm__ __volatile__(
			"mv sp, %[stack_top]\n"
			"j kernel_main\n"
			:
			: [stack_top] "r" (__stack_top)
		);
}

void handle_trap(struct trap_frame *f)
{
    uint32_t scause = READ_CSR(scause); // 어떤 이유로 예외가 발생했는지에 대한 정보
    uint32_t stval = READ_CSR(stval);   // 예외 부가 정보(잘못된 메모리, 주소)
    uint32_t user_pc = READ_CSR(sepc);  // 예외가 일어난 시점의 PC 정보

    PANIC("unexpected trap scause=%x, stval=%x, sepc=%x\n", scause, stval, user_pc);
}

__attribute__((naked))
__attribute__((aligned(4))) // 함수 시작 주소를 4바이트 경계에 맞추기 위함
void kernel_entry(void)
{
    __asm__ __volatile__(
        "csrw sscratch, sp\n"       // 현재 스택포인터를 임시 저장용 CSR인 sscratch에 저장
        "addi sp, sp, -4 * 31\n"    // 모든 레지스터(31개)를 저장할 공간을 스택에 확보
        "sw ra,  4 * 0(sp)\n"       // ra부터 s11까지 모든 일반 레지스터 값을 스택에 하나씩 (sw, store word) 저장
        "sw gp,  4 * 1(sp)\n"
        "sw tp,  4 * 2(sp)\n"
        "sw t0,  4 * 3(sp)\n"
        "sw t1,  4 * 4(sp)\n"
        "sw t2,  4 * 5(sp)\n"
        "sw t3,  4 * 6(sp)\n"
        "sw t4,  4 * 7(sp)\n"
        "sw t5,  4 * 8(sp)\n"
        "sw t6,  4 * 9(sp)\n"
        "sw a0,  4 * 10(sp)\n"
        "sw a1,  4 * 11(sp)\n"
        "sw a2,  4 * 12(sp)\n"
        "sw a3,  4 * 13(sp)\n"
        "sw a4,  4 * 14(sp)\n"
        "sw a5,  4 * 15(sp)\n"
        "sw a6,  4 * 16(sp)\n"
        "sw a7,  4 * 17(sp)\n"
        "sw s0,  4 * 18(sp)\n"
        "sw s1,  4 * 19(sp)\n"
        "sw s2,  4 * 20(sp)\n"
        "sw s3,  4 * 21(sp)\n"
        "sw s4,  4 * 22(sp)\n"
        "sw s5,  4 * 23(sp)\n"
        "sw s6,  4 * 24(sp)\n"
        "sw s7,  4 * 25(sp)\n"
        "sw s8,  4 * 26(sp)\n"
        "sw s9,  4 * 27(sp)\n"
        "sw s10, 4 * 28(sp)\n"
        "sw s11, 4 * 29(sp)\n"

        /* stack pointer 처리 */
        "csrr a0, sscratch\n"       // sscratch에 저장해놓은 sp 값을 a0로 가져옴
        "sw a0, 4 * 30(sp)\n"       // 스택의 마지막 인덱스 30에 원래 sp 값 저장

        "mv a0, sp\n"               // 현재 스택의 시작 주소를 a0에 저장
        "call handle_trap\n"        // handle_trap 함수 호출

        /* 상태(context) 복원 */
        "lw ra,  4 * 0(sp)\n"       // 스택에 저장해뒀던 값들을 레지스터에 다시 lw(load word) 로드 */
        "lw gp,  4 * 1(sp)\n"
        "lw tp,  4 * 2(sp)\n"
        "lw t0,  4 * 3(sp)\n"
        "lw t1,  4 * 4(sp)\n"
        "lw t2,  4 * 5(sp)\n"
        "lw t3,  4 * 6(sp)\n"
        "lw t4,  4 * 7(sp)\n"
        "lw t5,  4 * 8(sp)\n"
        "lw t6,  4 * 9(sp)\n"
        "lw a0,  4 * 10(sp)\n"
        "lw a1,  4 * 11(sp)\n"
        "lw a2,  4 * 12(sp)\n"
        "lw a3,  4 * 13(sp)\n"
        "lw a4,  4 * 14(sp)\n"
        "lw a5,  4 * 15(sp)\n"
        "lw a6,  4 * 16(sp)\n"
        "lw a7,  4 * 17(sp)\n"
        "lw s0,  4 * 18(sp)\n"
        "lw s1,  4 * 19(sp)\n"
        "lw s2,  4 * 20(sp)\n"
        "lw s3,  4 * 21(sp)\n"
        "lw s4,  4 * 22(sp)\n"
        "lw s5,  4 * 23(sp)\n"
        "lw s6,  4 * 24(sp)\n"
        "lw s7,  4 * 25(sp)\n"
        "lw s8,  4 * 26(sp)\n"
        "lw s9,  4 * 27(sp)\n"
        "lw s10, 4 * 28(sp)\n"
        "lw s11, 4 * 29(sp)\n"
        "lw sp,  4 * 30(sp)\n"
        /* Supervisor Resource Exception Return:
        이 명령어를 실행하면 CPU는 자동으로 sepc 레지스터에 저장된 주소(사고 지점)로 점프하고, 원래의 운영 모드(U 또는 S)로 돌아가게 됨
        */
        "sret\n"
    );
}

