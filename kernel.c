#include "kernel.h"
#include "common.h"

#define PROCS_MAX 8 // 최대 프로세스 개수

#define PROC_UNUSED 0 // 사용되지 않는 프로세스 구조체
#define PROC_RUNNABLE 1 // 실행 가능한(runnable) 프로세스


struct process procs[PROCS_MAX]; // 모든 프로세스 제어 구조체 배열

struct process *proc_a; // Process A
struct process *proc_b; // Process B

struct process *current_proc;   // 현재 실행 중인 프로세스
struct process *idle_proc;      // Idle 프로세스

void switch_context(uint32_t *prev_sp, uint32_t *next_sp);
void delay(void);
void putchar(char ch);
paddr_t alloc_pages(uint32_t n);
void kernel_entry(void);
void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags);

extern char __bss[], __bss_end[], __stack_top[];
extern char __free_ram[], __free_ram_end[]; // 메모리 할당 영역

extern char _binary_shell_bin_start[], _binary_shell_bin_size[];

void yield(void)
{
    // 실행 가능한 프로세스를 탐색
    struct process *next = idle_proc;
    for (int i = 0; i < PROCS_MAX; i++)
    {
        // 예: 현재 프로세스 PID:3 -> PCB 3, 4, 5, 6, 7, 0, 1, 2
        struct process *proc = &procs[(current_proc->pid + i) % PROCS_MAX];
        if (proc->state == PROC_RUNNABLE && proc->pid > 0)
        {
            next = proc;
            break;
        }
    }

    // 현재 프로세스 말고 실행 가능한 프로세스 없으면, 그냥 리턴
    if(next == current_proc)
    {
        return;
    }

    __asm__ __volatile__(
        "sfence.vma\n"
        "csrw satp, %[satp]\n"
        "sfence.vma\n"
        "csrw sscratch, %[sscratch]\n"
        :
        : [satp] "r" (SATP_SV32 | ((uint32_t) next->page_table / PAGE_SIZE)),
          [sscratch] "r" ((uint32_t) &next->stack[sizeof(next->stack)])
    );

    // 컨텍스트 스위칭
    struct process *prev = current_proc;
    current_proc = next;
    switch_context(&prev->sp, &next->sp);
}

__attribute__((naked)) void user_entry(void)
{
    __asm__ __volatile__(
        "csrw sepc, %[sepc]        \n"
        "csrw sstatus, %[sstatus]  \n"
        "sret                      \n"
        :
        : [sepc] "r" (USER_BASE),
          [sstatus] "r" (SSTATUS_SPIE)
    );
}

void proc_a_entry(void)
{
    printf("starting process A\n");
    while(1)
    {
        putchar('A');
        yield();
        //switch_context(&proc_a->sp, &proc_b->sp);
        delay();
    }
}

void proc_b_entry(void)
{
    printf("starting process B\n");
    while(1)
    {
        putchar('B');
        yield();
        //switch_context(&proc_b->sp, &proc_a->sp);
        delay();
    }
}



void delay(void)
{
    for(int i = 0; i < 30000000; i++)
    {
        __asm__ __volatile__("nop"); // do nothing
    }
}
//struct process* create_process(uint32_t pc)
struct process* create_process(const void *image, size_t image_size)
{
    // 미사용(UNUSED) 상태의 프로세스 구조체 찾기
    struct process *proc = NULL;
    int i;
    for(i = 0; i < PROCS_MAX; i++)
    {
        if(procs[i].state == PROC_UNUSED)
        {
            proc = &procs[i];
            break;
        }
    }

    /* 유휴상태의 프로세스 슬롯 검색 실패 */
    if(!proc)
    {
        PANIC("no free process slots");
    }

    // 커널 스택에 callee-saved 레지스터 공간을 미리 준비
    // 첫 컨텍스트 스위치 시, switch_context에서 이 값들을 복원함
    uint32_t *sp = (uint32_t *) &proc->stack[sizeof(proc->stack)]; // 스택포인터 꼭대기 위치
    /* 스택 포인터로부터 역순으로 callee-saved 레지스터 초기화 */
    *--sp = 0;                      // s11
    *--sp = 0;                      // s10
    *--sp = 0;                      // s9
    *--sp = 0;                      // s8
    *--sp = 0;                      // s7
    *--sp = 0;                      // s6
    *--sp = 0;                      // s5
    *--sp = 0;                      // s4
    *--sp = 0;                      // s3
    *--sp = 0;                      // s2
    *--sp = 0;                      // s1
    *--sp = 0;                      // s0
    //*--sp = (uint32_t) pc;          // ra (처음 실행 시 점프할 주소)
    *--sp = (uint32_t) user_entry;      // 처음 실행 시 점프할 주소

    // Map 커널 페이지
    uint32_t *page_table = (uint32_t *) alloc_pages(1);

    for(paddr_t paddr = (paddr_t) __kernel_base; paddr < (paddr_t)__free_ram_end; paddr += PAGE_SIZE)
    {
        map_page(page_table, paddr, paddr, PAGE_R | PAGE_W | PAGE_X);
    }

    // Map user pages.
    for (uint32_t off = 0; off < image_size; off += PAGE_SIZE)
    {
        paddr_t page = alloc_pages(1);

        // Handle the case where the data to be copied is smaller than the page size.
        size_t remaining = image_size - off;
        size_t copy_size = PAGE_SIZE <= remaining ? PAGE_SIZE : remaining;

        // Fill and map the page.
        memcpy((void *) page, image + off, copy_size);
        map_page(page_table, USER_BASE + off, page, PAGE_U | PAGE_R | PAGE_W | PAGE_X);
    }

    // 구조체 필드 초기화
    proc->pid = i + 1;
    proc->state = PROC_RUNNABLE;
    proc->sp = (uint32_t) sp;
    proc->page_table = page_table;
    return proc;
}



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

#if 1
void putchar(char ch){
	sbi_call(ch, 0, 0, 0, 0, 0, 0, 1 /* Console Putchar */);
}
#endif

long getchar(void)
{
    struct sbiret ret = sbi_call(0, 0, 0, 0, 0, 0, 0, 2);
    return ret.error;
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

void kernel_main(void)
{
	memset(__bss, 0x00, (size_t)__bss_end - (size_t)__bss);

    /*
	const char *s = "\r\n\nHello World!\r\n";
	for (int i = 0; s[i] != '\0'; i++){
		putchar(s[i]);
	}
    */

    /* stvec
    Supervisor Trap Vector: S-Mode에서 트랩(예외/인터럽트)이 발생했을 때 점프할 기본 주소를 담은 레지스터 */
    WRITE_CSR(stvec, (uint32_t) kernel_entry);
    //__asm__ __volatile__("unimp");

    // PID 0 process 생성
    //idle_proc = create_process((uint32_t) NULL);
    idle_proc = create_process(NULL, 0);
    idle_proc->pid = 0; // idle
    current_proc = idle_proc;

    /* process A, B 생성 */
    //proc_a = create_process((uint32_t) proc_a_entry); // 함수 주소를 넣음
    //proc_b = create_process((uint32_t) proc_b_entry);
    //proc_a_entry();

    create_process(_binary_shell_bin_start, (size_t) _binary_shell_bin_size);

    yield();

    PANIC("switched to idle process\n");


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

void handle_syscall(struct trap_frame *f)
{
    switch(f->a3) // a3에 syscall no 저장
    {
        case SYS_PUTCHAR:
        {
            putchar(f->a0); // a0 에 ch 저장
            break;
        }
        case SYS_GETCHAR:
        {
            while(1)
            {
                long ch = getchar();
                if(ch >= 0)
                {
                    f->a0 = ch;
                    break;
                }
                yield(); // 단순 반복 호출 시, 다른 프로세스가 실행 X, CPU를 양보
            }
            break;
        }
        case SYS_EXIT:
        {
            printf("process %d exited\n", current_proc->pid);
            current_proc->state = PROC_EXITED; // process 상태 변경
            yield(); // 다른 프로세스를 cpu에 양보
            PANIC("unreachable\n");
        }
        default:
        {
           PANIC("unexpected syscall a3=%x\n", f->a3); 
        }
    }
}

void handle_trap(struct trap_frame *f)
{
    uint32_t scause = READ_CSR(scause); // 어떤 이유로 예외가 발생했는지에 대한 정보
    uint32_t stval = READ_CSR(stval);   // 예외 부가 정보(잘못된 메모리, 주소)
    uint32_t user_pc = READ_CSR(sepc);  // 예외가 일어난 시점의 PC 정보

    // ecall 명령어 확인
    if (scause == SCAUSE_ECALL)
    {
        handle_syscall(f);
        user_pc += 4; // sepc가 예외를 발생시킨 명령어 가리킴. 변경 안할 시, ecall 명령어 반복
    }
    else
    {
        PANIC("unexpected trap scause=%x, stval=%x, sepc=%x\n", scause, stval, user_pc);
    }
    WRITE_CSR(sepc, user_pc);
}

// 예외 트랩 핸들러
__attribute__((naked))
__attribute__((aligned(4))) // 함수 시작 주소를 4바이트 경계에 맞추기 위함
void kernel_entry(void)
{
    __asm__ __volatile__(
        //"csrw sscratch, sp\n"       // 현재 스택포인터를 임시 저장용 CSR인 sscratch에 저장
        "csrrw sp, sscratch, sp\n"       // Control and Status Register Read and Write, "CPU의 sp 레지스터와 sscratch 레지스터의 값을 서로 맞바꿔라(Swap)"
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

        // Reset the kernel stack.
        "addi a0, sp, 4 * 31\n"
        "csrw sscratch, a0\n"

        "mv a0, sp\n"               // 현재 스택의 시작 주소를 a0에 저장
        "call handle_trap\n"        // handle_trap 함수 호출

        /* 상태(context) 복원 */
        "lw ra,  4 * 0(sp)\n"       // 스택에 저장해뒀던 값들을 레지스터에 다시 lw(load word) 로드 */
     
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

__attribute__((naked))
void switch_context(uint32_t *prev_sp, uint32_t *next_sp)
{
    __asm__ __volatile__(
       // 현재 프로세스의 스택에 callee-saved 레지스터를 저장
       "addi sp, sp, -13 * 4\n" // 13개(4바이트씩) 레지스터 공간 확보
        "sw ra,  0  * 4(sp)\n"   // callee-saved 레지스터만 저장
        "sw s0,  1  * 4(sp)\n"
        "sw s1,  2  * 4(sp)\n"
        "sw s2,  3  * 4(sp)\n"
        "sw s3,  4  * 4(sp)\n"
        "sw s4,  5  * 4(sp)\n"
        "sw s5,  6  * 4(sp)\n"
        "sw s6,  7  * 4(sp)\n"
        "sw s7,  8  * 4(sp)\n"
        "sw s8,  9  * 4(sp)\n"
        "sw s9,  10 * 4(sp)\n"
        "sw s10, 11 * 4(sp)\n"
        "sw s11, 12 * 4(sp)\n"

        // 스택 포인터 교체
        "sw sp, (a0)\n"         // *prev_sp = sp
        "lw sp, (a1)\n"         // sp를 다음 프로세스의 값으로 변경

        // 다음 프로세스 스택에서 callee-saved 레지스터 복원
        "lw ra,  0  * 4(sp)\n"
        "lw s0,  1  * 4(sp)\n"
        "lw s1,  2  * 4(sp)\n"
        "lw s2,  3  * 4(sp)\n"
        "lw s3,  4  * 4(sp)\n"
        "lw s4,  5  * 4(sp)\n"
        "lw s5,  6  * 4(sp)\n"
        "lw s6,  7  * 4(sp)\n"
        "lw s7,  8  * 4(sp)\n"
        "lw s8,  9  * 4(sp)\n"
        "lw s9,  10 * 4(sp)\n"
        "lw s10, 11 * 4(sp)\n"
        "lw s11, 12 * 4(sp)\n"
        "addi sp, sp, 13 * 4\n"
        "ret\n"
    );
}

void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags)
{
    // 가상 메모리와 물리 메모리는 4KB(PAGE_SIZE) 로 관리
    // 주소의 하위 12비트는 Offset으로 사용, 매핑할 주소의 하위 12비트가 0이 아니면 오작동
    if (!is_aligned(vaddr, PAGE_SIZE))
    {
        PANIC("unaligned vaddr %x", vaddr);
    }

    if (!is_aligned(paddr, PAGE_SIZE))
    {
        PANIC("unaligned paddr %x", paddr);
    }
    
    uint32_t vpn1 = (vaddr >> 22) & 0x3FF; // 상위 10비트 추출, 1단계 테이블 인덱스로 사용
    if((table1[vpn1] & PAGE_V) == 0)         // 2단계 테이블이 아직 없음
    {
        uint32_t pt_paddr = alloc_pages(1); // 2단계 테이블로 쓸 새로운 페이지 할당
        table1[vpn1] = ((pt_paddr / PAGE_SIZE) << 10) | PAGE_V; // 새로운 2단계 페이지의 주소를 1단계 테이블에 등록
        // 주소를 PAGE_SIZE로 나누는 이유는 PTE에 주소 전체가 아닌 PPN (페이지 번호)를 넣어야 하기 때문
    }

    // 2단계 페이지 테이블 엔트리에 물리 페이지 번호와 플래그 설정
    uint32_t vpn0 = (vaddr >> 12) & 0x3FF;
    uint32_t *table0 = (uint32_t *)((table1[vpn1] >> 10) * PAGE_SIZE); // 2단계 테이블 주소 계산
    table0[vpn0] = ((paddr / PAGE_SIZE) << 10) | flags | PAGE_V; // 최종 물리 주소 매핑
}
