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

// kernel.h

// 상수 및 레지스터 정의 (MMIO)
#define SECTOR_SIZE       512    // 디스크 읽기/쓰기 기본 단위 (512바이트)
#define VIRTQ_ENTRY_NUM   16     // Virtqueue 내 디스크립터 개수 (큐의 크기)
#define VIRTIO_DEVICE_BLK 2      // VirtIO 장치 유형 중 '블록 장치'를 의미하는 ID
#define VIRTIO_BLK_PADDR  0x10001000 // QEMU virt 머신에서 블록 장치가 매핑된 MMIO 시작 주소

// VirtIO 제어 레지스터 오프셋 (VIRTIO_BLK_PADDR로부터의 거리)
#define VIRTIO_REG_MAGIC         0x00   // 매직 넘버 (0x74726976, "virt"인지 확인용)
#define VIRTIO_REG_VERSION       0x04   // 장치 버전 정보
#define VIRTIO_REG_DEVICE_ID     0x08   // 장치 종류 ID (2면 블록 장치)
#define VIRTIO_REG_PAGE_SIZE     0x28   // 게스트의 페이지 크기 설정
#define VIRTIO_REG_QUEUE_SEL     0x30   // 설정을 변경할 큐 선택
#define VIRTIO_REG_QUEUE_NUM_MAX 0x34   // 선택된 큐의 최대 크기 확인
#define VIRTIO_REG_QUEUE_NUM     0x38   // 사용할 큐의 크기 설정
#define VIRTIO_REG_QUEUE_PFN     0x40   // 큐의 물리 주소(페이지 번호) 설정
#define VIRTIO_REG_QUEUE_READY   0x44   // 큐 사용 준비 완료 신호
#define VIRTIO_REG_QUEUE_NOTIFY  0x50   // 장치에게 큐를 확인하라고 알림 (Kick)
#define VIRTIO_REG_DEVICE_STATUS 0x70   // 장치 상태(초기화 단계) 설정 및 확인
#define VIRTIO_REG_DEVICE_CONFIG 0x100  // 장치별 특수 설정 영역 시작점

// 장치 상태 비트
#define VIRTIO_STATUS_ACK        1      // 장치를 인식함
#define VIRTIO_STATUS_DRIVER     2      // 드라이버가 어떻게 구동할지 알고 있음
#define VIRTIO_STATUS_DRIVER_OK  4      // 드라이버 초기화 완료 및 작동 시작

// 디스크립터 플래그
#define VIRTQ_DESC_F_NEXT          1    // 다음 디스크립터가 이어진다는 표시 (Chaining)
#define VIRTQ_DESC_F_WRITE         2    // 장치가 이 메모리에 값을 쓴다는 표시 (디스크 읽기 시 사용)

// Avail 링 플래그
#define VIRTQ_AVA_F_NO_INTERRUPT 1    // 처리가 끝나도 인터럽트를 발생시키지 말라는 요청

// 블록 장치 요청 타입
#define VIRTIO_BLK_T_IN  0              // 디스크 읽기
#define VIRTIO_BLK_T_OUT 1              // 디스크 쓰기

// filesystem

#define FILES_MAX      2 // OS가 동시에 관리할 수 있는 최대 파일 개수이다.
// 파일 데이터 구조체들을 담기에 충분한 디스크 공간 크기를 계산하며, 섹터 단위로 올림 처리한다.
#define DISK_MAX_SIZE  align_up(sizeof(struct file) * FILES_MAX, SECTOR_SIZE)

#define SSTATUS_SUM (1 << 18)

struct tar_header {
    char name[100];   // 파일의 경로를 포함한 이름이다.
    char mode[8];     // 파일의 권한(8진수 문자열)이다.
    char uid[8];      // 사용자 ID(8진수 문자열)이다.
    char gid[8];      // 그룹 ID(8진수 문자열)이다.
    char size[12];    // 파일 데이터의 크기(8진수 문자열)이다.
    char mtime[12];   // 마지막 수정 시간(8진수 문자열)이다.
    char checksum[8]; // 헤더의 유효성을 검사하기 위한 체크섬이다.
    char type;        // 파일의 종류(일반 파일, 디렉터리 등)를 나타내는 플래그이다.
    char linkname[100]; // 심볼릭 링크 시 연결된 대상 파일의 이름이다.
    char magic[6];    // "ustar" 문자열이 들어가는 포맷 식별자이다.
    char version[2];  // ustar 포맷의 버전이다.
    char uname[32];   // 소유자 사용자 이름이다.
    char gname[32];   // 소유자 그룹 이름이다.
    char devmajor[8]; // 장치 파일일 경우의 메이저 번호이다.
    char devminor[8]; // 장치 파일일 경우의 마이너 번호이다.
    char prefix[155]; // 파일 이름이 100자를 넘을 경우 사용하는 접두사 영역이다.
    char padding[12]; // 헤더 구조체 크기를 맞추기 위한 패딩이다.
    char data[];      // Array pointing to the data area following the header
                      // (flexible array member)
} __attribute__((packed)); // 컴파일러의 비트 정렬 최적화를 방지하여 바이너리 규격을 강제한다.

struct file {
    bool in_use;      // Indicates if this file entry is in use
    char name[100];   // File name
    char data[1024];  // File content
    size_t size;      // File size
};

// virtqueue 구조체

// Virtqueue Descriptor Table entry: 데이터의 위치와 크기 정보를 담는 칸
struct virtq_desc {
    uint64_t addr;  // 데이터가 저장된 메모리의 물리 주소
    uint32_t len;   // 데이터의 길이
    uint16_t flags; // NEXT, WRITE 등 플래그
    uint16_t next;  // 다음 디스크립터 번호 (Chaining 시 사용)
} __attribute__((packed));

// Virtqueue Available Ring: 드라이버가 장치에게 줄 작업 목록
struct virtq_avail {
    uint16_t flags;
    uint16_t index; // 다음에 쓸 링의 인덱스
    uint16_t ring[VIRTQ_ENTRY_NUM]; // 디스크립터 번호들의 배열
} __attribute__((packed));

// Virtqueue Used Ring entry: 장치가 처리를 완료한 항목 정보
struct virtq_used_elem {
    uint32_t id;    // 완료된 디스크립터 체인의 시작 번호
    uint32_t len;   // 장치가 쓴 데이터의 총 길이
} __attribute__((packed));

// Virtqueue Used Ring: 장치가 드라이버에게 돌려줄 작업 완료 목록
struct virtq_used {
    uint16_t flags;
    uint16_t index; // 장치가 다음에 쓸 인덱스
    struct virtq_used_elem ring[VIRTQ_ENTRY_NUM];
} __attribute__((packed));

// Virtqueue 전체 구조: 세 영역을 하나로 묶음
struct virtio_virtq {
    struct virtq_desc descs[VIRTQ_ENTRY_NUM]; // 디스크립터 테이블
    struct virtq_avail avail;                 // Avail 링
    struct virtq_used used __attribute__((aligned(PAGE_SIZE))); // Used 링 (페이지 정렬 필수)
    int queue_index;            // 큐 번호
    volatile uint16_t *used_index; // 장치가 갱신하는 Used 인덱스를 가리키는 포인터
    uint16_t last_used_index;   // 드라이버가 마지막으로 확인한 Used 인덱스
} __attribute__((packed));

// 디스크 요청 구조체

// 장치에 보낼 읽기/쓰기 요청 데이터 구조체
struct virtio_blk_req {
    // 첫 번째 디스크립터: 장치에게 보낼 명령 헤더 영역 (장치는 이 영역을 읽기만 함)
    // 드라이버(커널)가 요청 종류(type)와 접근할 위치(sector)를 기입하여 장치에 전달한다.
    uint32_t type;     // VIRTIO_BLK_T_IN(읽기) 또는 VIRTIO_BLK_T_OUT(쓰기)
    uint32_t reserved; // 하드웨어 규약상 0으로 채워야 하는 예약 영역
    uint64_t sector;   // 읽거나 쓰고자 하는 디스크의 섹터 번호

    // 두 번째 디스크립터: 실제 데이터가 오가는 버퍼 영역
    // 읽기(IN) 작업 시에는 장치가 이 메모리에 값을 써야 하므로 VIRTQ_DESC_F_WRITE 속성이 필수적이다.
    // 쓰기(OUT) 작업 시에는 드라이버가 쓴 내용을 장치가 읽어가기만 하면 되므로 해당 플래그를 끈다.
    uint8_t data[512];

    // 세 번째 디스크립터: 장치가 작업 결과를 보고하는 상태 정보 영역
    // 장치는 작업이 끝나면 성공 여부를 이 영역에 직접 기록해야 한다.
    // 따라서 이 디스크립터에는 항상 장치의 쓰기 권한(VIRTQ_DESC_F_WRITE)이 부여되어야 한다.
    uint8_t status;    // 0이면 성공, 그 외의 값은 에러를 의미한다.
} __attribute__((packed));

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
