#include "stdio.h"
#include "protect.h"
#include "proc.h"
#include "global.h"
#include "proto.h"

static void 
kprintfputch(int ch, void *b)
{
	char buf[2]={(char)ch,'\0'};
	disp_str(buf);
}

int
vkprintf(const char *fmt, va_list ap)
{

	vprintfmt((void*)kprintfputch, NULL, fmt, ap);

	return 0;
}

int
kprintf(const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vkprintf(fmt, ap);
	va_end(ap);

	return rc;
}