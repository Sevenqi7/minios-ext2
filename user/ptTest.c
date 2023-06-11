#include "stdio.h"

int global=0;

char *str2,*str3;

void delay(int x)
{
	int i, j;
	for(i=0;i<x;i++)
		for(j=0;j<1000000;j++);
}

void pthread_test1()
{
	int i;
	// pthread(pthread_test2);
	while(1)
	{
		printf("pthread 1:");
		printf("%d\n",++global);
		delay(1000);
	}
}

/*======================================================================*
                          Syscall Pthread Test
added by xw, 18/4/27
 *======================================================================*/

int main(int arg,char *argv[])
{
	int i=0;
	
	pthread(pthread_test1);
	return 0;
}
