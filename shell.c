#include "user.h"

void main(void)
{
      //*((volatile int *) 0x80200000) = 0x1234; // new!
      printf("Hello world from shell!\n");
    //for(;;);

prompt:
    printf("> ");
    char cmdline[128];
    for(int i = 0;; i++)
    {
        char ch = getchar();
        putchar(ch); // 입력시 화면에 출력
        if(i == sizeof(cmdline) - 1)
        {
            printf("command line too long\n");
            goto prompt;
        }
        else if( ch == '\r' ) // debug consol 에서는 줄바꿈 문자가 '\r' 임
        {
            printf("\n");
            cmdline[i] = '\0';
            break;
        }
        else
        {
            cmdline[i] = ch;
        }
    }
    if(strcmp(cmdline, "hello") == 0)
    {
        printf("Hello world from shell!!\n");
    }
    else if (strcmp(cmdline, "readfile") == 0)
    {
        char buf[128];
        int len = readfile("hello.txt", buf, sizeof(buf));
        buf[len] = '\0';
        printf("%s\n", buf);
    }
    else if (strcmp(cmdline, "writefile") == 0)
    {
        writefile("hello.txt", "Hello from shell!\n", 19);
    }
    else if(strcmp(cmdline, "exit") == 0)
    {
        exit();
    }
    else
    {
        printf("Unknown command: %s\n", cmdline);
    }
}
