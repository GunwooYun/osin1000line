ENTRY(boot)

SECTIONS {
	. = 0x80200000; /* BASE ADDRESS */

	/* 코드가 저장되는 섹션 */
	.text :{ 
		/* 모든 입력파일에서 .text.boot 섹션을 가져와 앞에 배치
		 * KEEP은 최적화 과정에서 삭제하지 말고 유지 */
		KEEP(*(.text.boot)); 
		/* 일반적인 함수 코드들(.text)와 컴파일러가 생성한 .text.* 배치 */
		*(.text .text.*);
	}

	/* 읽기 전용 데이터 리터럴 상수 or const 저장 섹션 */
	.rodata : ALIGN(4) { /* <- 섹션 배치 전 4바이트 단위 정렬 */
		*(.rodata .rodata.*);
	}

	/* 초기값이 있는 전역변수와 정적변수 저장 섹션 */
	.data : ALIGN(4) {
		*(.data .data.*);
	}

	/* 초기화되지 않은 전역변수 섹션 */
	.bss : ALIGN(4) {
		__bss = .; /* .bss 섹션 시작 주소 */
		/* sbss: small bss, RISC-V에서 전역 포인터를 통해 빠르게 접근 */
		*(.bss .bss.* .sbss .sbss.*); 
		__bss_end = .; /* .bss 섹션 끝 주소 */
	}

	. = ALIGN(4); /* 4바이트 정렬 */
	. += 128 * 1024; /* Stack size: 128KB */
	__stack_top = .; /* 확보된 메모리 공간 마지막 주소를 stack top 포인터로 지정 */

    . = ALIGN(4096);
    __free_ram = .; /* 메모리 할당 시작 주소 */
    . += 64 * 1024 * 1024; /* 64MB */
    __free_ram_end = .; /* 메모리 할당 끝 주소 */

}
