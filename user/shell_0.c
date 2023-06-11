#include "type.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "proc.h"
#include "global.h"
#include "proto.h"
#include "stdio.h"

char path_buf[128] = "ext2/";

int main(int arg, char *argv[])
{
	printf("--------Shell Start------- \n");
	int stdin = open("dev_tty0", O_RDWR);
	int stdout = open("dev_tty0", O_RDWR);
	int stderr = open("dev_tty0", O_RDWR);


	char dirent[1024], buf[1024];
	struct linux_dirent *dirp = (struct linux_dirent *)dirent;
	int pid;
	int times = 0;

	while (1)
	{
		int current_directory = open(path_buf, O_RDWR);
		getdents(current_directory, (struct linux_dirent *)&dirent, 1024);
		dirp = (struct linux_dirent *)dirent;
		printf("\nminiOS:%s $ ", path_buf);
		if (gets(buf) && strlen(buf) != 0)
		{
			// if (exec(buf) != 0)
			// {
			// 	printf("exec failed: file not found!\n");
			// 	continue;
			// }
			char *pbuf = buf;
			while(*pbuf == ' ')
				pbuf++;
			if(!strncmp("cd ", pbuf, 3))
			{
				char *path;
				int i;
				path = &pbuf[3];
				while(*path == ' ')
					path++;
				for(i=0;path[i];i++)
					if(path[i] == ' ')
						path[i] = '\0';
				for(i=0;i<1024;i++)
				{
					if(!dirp->d_reclen)
					{
						printf("No such directory\n");
						break;
					}
					else if(!strcmp(path, dirp->d_name))
					{
						if(!strcmp(dirp->d_name, "."))
							break;
						else if(!strcmp(dirp->d_name, ".."))
						{
							int i = strlen(path_buf) - 1;
							while(path_buf[i] != '/')
								i--;
							if(i != 4)
								path_buf[i] = '\0';
							else
								path_buf[i+1] = '\0';
							break;
						}
						else 
						{
							if(strcmp(path_buf, "ext2/"))
								strcat(path_buf, "/");
							strcat(path_buf, path);
						}
						close(current_directory);
						break;
					}
					dirp = (struct linux_dirent *)((char *)dirp + dirp->d_reclen);
					i += dirp->d_reclen;
				}
			}
			else if(!strncmp(pbuf, "ls ", 3) || !strcmp(pbuf, "ls"))
			{
				struct linux_dirent *_dirp = dirp;
				printf("Directory: ");
				while(_dirp->d_reclen)
				{
					if(_dirp->d_type == DIRENT_DIR)
						printf("%s   ", _dirp->d_name);
					_dirp = (struct linux_dirent *)((char *)_dirp + _dirp->d_reclen);
				}
				printf("\n");
				printf("Regular File: ");
				_dirp = dirp;
				while(_dirp->d_reclen)
				{
					if(_dirp->d_type == DIRENT_REG)
						printf("%s   ", _dirp->d_name);
					_dirp = (struct linux_dirent *)((char *)_dirp + _dirp->d_reclen);
				}
				printf("\n");
			}
			else if(!strncmp(pbuf, "touch ", 6))
			{
				char *filename = &pbuf[6];
				char fullpath[128];
				memcpy(fullpath, path_buf, strlen(path_buf)+1);
				while(*filename == ' ')
					filename++;
				if(strcmp(path_buf, "ext2/"))
					strcat(fullpath, "/");
				strcat(fullpath, filename);
				int fd = open(fullpath, O_RDWR);
				if(fd != -1)
					printf("touch: %s already exists.\n", filename);
				else
					fd = create(fullpath);
				close(fd);
			}
			else if(!strncmp(pbuf, "cat ", 4))
			{
				char *filename = &pbuf[4];
				char fullpath[128];
				memcpy(fullpath, path_buf, strlen(path_buf)+1);
				while(*filename == ' ')
					filename++;
				if(strcmp(path_buf, "ext2/"))
					strcat(fullpath, "/");
				strcat(fullpath, filename);
				int fd = open(fullpath, O_RDWR);
				if(fd == -1)
					printf("cat: file %s doesn't extist.\n", filename);
				else
				{
					char read_buf[1500];
					lseek(fd, 0, SEEK_SET);
					int sum=0;
					int read_len = read(fd, read_buf, 512);
					sum += read_len;
					if(read_len)
					{
						read_buf[read_len] = '\0';
						printf("%s", read_buf);
						memset(read_buf, 0, 1500);
						while(read_len)
						{
							read_len = read(fd, read_buf, 512);
							read_buf[read_len] = '\0';
							printf("\n");
							printf("--------Press enter to see more--------  read_bytes:%d\n", sum);
							while(getchar() != '\n');
							sum += read_len;
							printf("%s", read_buf);
							memset(read_buf, 0, 1500);
						}
						printf("\n");
					}
					close(fd);	
				}
			}
			else if(!strncmp(pbuf, "rm ", 3))
			{
				char *filename = &pbuf[3];
				char fullpath[128];
				memcpy(fullpath, path_buf, strlen(path_buf)+1);
				while(*filename == ' ')
					filename++;
				if(strcmp(path_buf, "ext2/"))
					strcat(fullpath, "/");
				strcat(fullpath, filename);
				if(unlink(fullpath) == -1)
					printf("Failed to delete %s\n", filename);
			}
			else if(!strncmp(pbuf, "exec ", 5))
			{
				char *path = &pbuf[5];
				while(*path == ' ')
					path++;
				exec(path);
			}
			else if(!strncmp(pbuf, "mkdir ", 6))
			{
				char *dirname = &pbuf[6];
				char fullpath[128];
				memcpy(fullpath, path_buf, strlen(path_buf)+1);
				while(*dirname == ' ')
					dirname++;
				if(strcmp(path_buf, "ext2/"))
					strcat(fullpath, "/");
				strcat(fullpath, dirname);
				if(!createdir(fullpath))
					printf("Failed to create directory.\n");
			}
			else if(!strncmp(pbuf, "writetest ", 10))
			{
				char *filename = &pbuf[10];
				char fullpath[128];
				memcpy(fullpath, path_buf, strlen(path_buf)+1);
				while(*filename == ' ')
					filename++;
				if(strcmp(path_buf, "ext2/"))
					strcat(fullpath, "/");
				strcat(fullpath, filename);
				printf("%s", fullpath);
				char file_buf[2048];
				memset(file_buf, 0, 2048);
				int fd = open(fullpath, O_RDWR);
				if(fd != -1)
				{
					int fd2 = create("ext2/writetest");
					lseek(fd2, 0, SEEK_SET);
					int read_len = read(fd, file_buf, 2048);
					while(read_len)
					{
						write(fd2, file_buf, read_len);
						read_len = read(fd, file_buf, 2048);
					}
					printf("writetest finish.\n");
					close(fd2);
				}
			}
			else
				printf("Unknown command.\n");
			memset(buf, 0, 1024);
		}
	}
}