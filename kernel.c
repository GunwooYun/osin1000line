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

struct virtio_virtq *blk_request_vq; // 블록 장치와 통신할 가상 큐(Virtqueue) 구조체 포인터
struct virtio_blk_req *blk_req;      // 장치에 보낼 읽기/쓰기 요청 데이터 구조체 포인터
paddr_t blk_req_paddr;              // 요청 데이터가 저장된 영역의 물리 주소
uint64_t blk_capacity;               // 연결된 디스크의 전체 용량 (바이트 단위)

// VirtIO 장치의 32비트 레지스터에 특정 값을 쓰는 함수
void virtio_reg_write32(unsigned offset, uint32_t value);
// VirtIO 장치의 32비트 레지스터 값을 읽어오는 함수
uint32_t virtio_reg_read32(unsigned offset);
// VirtIO 장치의 64비트 레지스터 값을 읽어오는 함수
uint64_t virtio_reg_read64(unsigned offset);

// 특정 레지스터의 기존 값을 유지하면서 특정 비트만 1로 설정(OR 연산)하는 함수
void virtio_reg_fetch_and_or32(unsigned offset, uint32_t value);

// 장치가 요청을 처리 중인지 확인합니다.
bool virtq_is_busy(struct virtio_virtq *vq) {
    // 드라이버가 예상하는 인덱스와 장치가 실제 완료한 인덱스가 다르면 아직 처리 중인 것이다.
    return vq->last_used_index != *vq->used_index;
}


struct virtio_virtq *virtq_init(unsigned index) {
    // Virtqueue 구조체 크기만큼 물리 메모리 페이지를 할당받는다.
    // 구조체 내부에 PAGE_SIZE 정렬이 필요한 멤버(used)가 있으므로 정렬하여 할당한다.
    paddr_t virtq_paddr = alloc_pages(align_up(sizeof(struct virtio_virtq), PAGE_SIZE) / PAGE_SIZE);

    // 할당받은 물리 주소를 가상 큐 구조체 포인터로 사용한다.
    struct virtio_virtq *vq = (struct virtio_virtq *) virtq_paddr;

    // 가상 큐의 고유 번호를 저장한다.
    vq->queue_index = index;

    // 장치(Device)가 처리 완료 후 갱신할 Used Ring의 인덱스 위치를 가리키도록 설정한다.
    vq->used_index = (volatile uint16_t *) &vq->used.index;

    // 큐 선택: virtqueue 인덱스를 기록 (첫 번째 큐는 0)
    virtio_reg_write32(VIRTIO_REG_QUEUE_SEL, index);

    // 큐 크기 지정: 사용할 디스크립터 개수를 기록
    virtio_reg_write32(VIRTIO_REG_QUEUE_NUM, VIRTQ_ENTRY_NUM);

    // 큐의 페이지 프레임 번호 (물리 주소가 아님!) 를 기록
    // 물리 주소를 PAGE_SIZE로 나누어 PFN(Page Frame Number)으로 변환하여 등록한다.
    virtio_reg_write32(VIRTIO_REG_QUEUE_PFN, virtq_paddr / PAGE_SIZE);

    return vq;
}

void virtio_blk_init(void) {
    // 장치의 Magic Value를 확인하여 VirtIO 장치가 맞는지 검증한다. (0x74726976는 "virt"의 리틀 엔디언 표현이다.)
    if (virtio_reg_read32(VIRTIO_REG_MAGIC) != 0x74726976)
        PANIC("virtio: invalid magic value");
    // VirtIO 레거시 버전(1)을 사용하는지 확인한다.
    if (virtio_reg_read32(VIRTIO_REG_VERSION) != 1)
        PANIC("virtio: invalid version");
    // 장치 ID가 2(Block Device)인지 확인하여 디스크 장치가 맞는지 검증한다.
    if (virtio_reg_read32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_BLK)
        PANIC("virtio: invalid device id");

    // 1. 장치를 리셋하여 초기 상태로 만든다.
    virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, 0);
    // 2. ACKNOWLEDGE 상태 비트 설정: OS가 장치를 인식했음을 하드웨어에 알린다.
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    // 3. DRIVER 상태 비트 설정: OS에 해당 장치를 구동할 드라이버가 있음을 알린다.
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);
    // 페이지 크기 설정: 하드웨어가 주소 변환(PFN)을 할 수 있도록 시스템의 페이지 크기를 알려준다.
    virtio_reg_write32(VIRTIO_REG_PAGE_SIZE, PAGE_SIZE);

    // 0번 가상 큐를 초기화하고 메모리 주소를 장치에 등록한다.
    blk_request_vq = virtq_init(0);

    // 6. DRIVER_OK 상태 비트 설정: 드라이버 초기화가 완료되었으며, 이제부터 입출력이 가능함을 알린다.
    virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER_OK);

    // 장치의 설정 영역(Config Space)에서 섹터 개수를 읽어와 전체 바이트 용량을 계산한다.
    blk_capacity = virtio_reg_read64(VIRTIO_REG_DEVICE_CONFIG + 0) * SECTOR_SIZE;
    printf("virtio-blk: capacity is %d bytes\n", (int)blk_capacity);

    // 장치와 데이터를 주고받을 때 사용할 요청(request) 구조체 메모리를 할당한다.
    // 구조체 크기를 페이지 단위로 올림(align_up)하여 필요한 페이지 수를 계산한다.
    blk_req_paddr = alloc_pages(align_up(sizeof(*blk_req), PAGE_SIZE) / PAGE_SIZE);
    // 할당받은 물리 주소를 구조체 포인터에 대입하여 커널에서 접근할 수 있도록 한다.
    blk_req = (struct virtio_blk_req *) blk_req_paddr;
}

// VirtIO 장치의 32비트 레지스터 값을 읽어오는 함수
uint32_t virtio_reg_read32(unsigned offset) {
    // 기본 주소(0x10001000)에 오프셋을 더해 해당 레지스터의 메모리 주소로 접근해 값을 반환한다.
    // volatile은 컴파일러가 이 접근을 최적화해서 생략하지 않도록 강제하는 역할을 한다.
    return *((volatile uint32_t *) (VIRTIO_BLK_PADDR + offset));
}

// VirtIO 장치의 64비트 레지스터 값을 읽어오는 함수
uint64_t virtio_reg_read64(unsigned offset) {
    // 32비트와 동일하지만, 한 번에 8바이트(64비트) 데이터를 읽어온다.
    return *((volatile uint64_t *) (VIRTIO_BLK_PADDR + offset));
}

// VirtIO 장치의 32비트 레지스터에 특정 값을 쓰는 함수
void virtio_reg_write32(unsigned offset, uint32_t value) {
    // 특정 레지스터 주소에 value를 대입하여 하드웨어에게 명령을 전달한다.
    *((volatile uint32_t *) (VIRTIO_BLK_PADDR + offset)) = value;
}

// 특정 레지스터의 기존 값을 유지하면서 특정 비트만 1로 설정(OR 연산)하는 함수
void virtio_reg_fetch_and_or32(unsigned offset, uint32_t value) {
    // 현재 레지스터 값을 읽어온(read) 뒤, 넘겨받은 값과 OR 연산(|)을 하고 다시 써넣는다.(write).
    // 주로 장치의 상태 비트(Status bit)를 하나씩 추가로 활성화할 때 사용한다.
    virtio_reg_write32(offset, virtio_reg_read32(offset) | value);
}

// desc_index는 새로운 요청의 디스크립터 체인의 헤드 디스크립터 인덱스입니다.
// 장치에 새로운 요청이 있음을 알립니다.
void virtq_kick(struct virtio_virtq *vq, int desc_index) {
    // Available Ring의 현재 인덱스 위치에 처리할 디스크립터 번호를 등록한다.
    vq->avail.ring[vq->avail.index % VIRTQ_ENTRY_NUM] = desc_index;
    // 드라이버가 다음 번에 사용할 링 인덱스를 1 증가시킨다.
    vq->avail.index++;
    // 메모리 장벽(Memory Barrier): 위 데이터가 메모리에 완전히 기록된 후 아래 레지스터 쓰기가 발생하도록 보장한다.
    __sync_synchronize();
    // 장치의 Notify 레지스터에 큐 번호를 써서 장치에게 처리를 시작하라고 알린다. (Kick)
    virtio_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, vq->queue_index);
    // 드라이버 입장에서 장치가 처리해야 할 항목이 하나 늘었음을 기록한다.
    vq->last_used_index++;
}

// virtio-blk 장치로부터 읽기/쓰기를 수행합니다.
void read_write_disk(void *buf, unsigned sector, int is_write) {
    // 요청한 섹터 번호가 디스크 용량 범위를 넘어서는지 확인한다.
    if (sector >= blk_capacity / SECTOR_SIZE) {
        printf("virtio: tried to read/write sector=%d, but capacity is %d\n",
              sector, blk_capacity / SECTOR_SIZE);
        return;
    }

    // virtio-blk 사양에 따라 요청을 구성합니다.
    blk_req->sector = sector;
    blk_req->type = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    // 쓰기 작업일 경우, 전달받은 버퍼의 데이터를 공용 요청 영역(blk_req)으로 복사한다.
    if (is_write)
        memcpy(blk_req->data, buf, SECTOR_SIZE);

    // virtqueue 디스크립터를 구성합니다 (3개의 디스크립터 사용).
    // 첫 번째 디스크립터: 요청 헤더 (type, reserved, sector 정보)
    struct virtio_virtq *vq = blk_request_vq;
    vq->descs[0].addr = blk_req_paddr;
    vq->descs[0].len = sizeof(uint32_t) * 2 + sizeof(uint64_t);
    vq->descs[0].flags = VIRTQ_DESC_F_NEXT; // 다음 디스크립터(데이터)로 이어진다.
    vq->descs[0].next = 1;

    // 두 번째 디스크립터: 실제 데이터 영역
    vq->descs[1].addr = blk_req_paddr + offsetof(struct virtio_blk_req, data);
    vq->descs[1].len = SECTOR_SIZE;
    // 읽기 작업일 경우 장치가 이 메모리에 값을 써야 하므로 VIRTQ_DESC_F_WRITE 플래그를 추가한다.
    vq->descs[1].flags = VIRTQ_DESC_F_NEXT | (is_write ? 0 : VIRTQ_DESC_F_WRITE);
    vq->descs[1].next = 2;

    // 세 번째 디스크립터: 상태 결과 (장치가 작업 성공 여부를 적어줄 공간)
    vq->descs[2].addr = blk_req_paddr + offsetof(struct virtio_blk_req, status);
    vq->descs[2].len = sizeof(uint8_t);
    // 장치가 결과를 써야 하므로 무조건 WRITE 플래그가 필요하며, 체인의 마지막이므로 NEXT 플래그는 없다.
    vq->descs[2].flags = VIRTQ_DESC_F_WRITE;

    // 장치에 새로운 요청이 있음을 알림.
    virtq_kick(vq, 0);

    // 장치가 요청 처리를 마칠 때까지 대기(바쁜 대기; busy-wait).
    while (virtq_is_busy(vq))
        ;

    // virtio-blk: 0이 아닌 값이 반환되면 에러입니다.
    if (blk_req->status != 0) {
        printf("virtio: warn: failed to read/write sector=%d status=%d\n",
               sector, blk_req->status);
        return;
    }

    // 읽기 작업의 경우, 장치가 채워준 데이터를 사용자의 버퍼로 복사한다.
    if (!is_write)
        memcpy(buf, blk_req->data, SECTOR_SIZE);
}

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

    map_page(page_table, VIRTIO_BLK_PADDR, VIRTIO_BLK_PADDR, PAGE_R | PAGE_W); // new

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

    virtio_blk_init(); // virtio-blk 장치 초기화

    char buf[SECTOR_SIZE];
    read_write_disk(buf, 0, false /* read from the disk */);
    printf("first sector: %s\n", buf);

    strcpy(buf, "hello from kernel!!!\n");
    read_write_disk(buf, 0, true /* write to the disk */);

#if 0
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
#endif

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
