#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main()
{
  int fd;
  char c[] = "R|||/home/test/testdir/test_runtime:::\n|||/home/test/testdir/test_config:::/home/test/testdir/config\n";
  fd = open("/proc/lsm_ctl",O_RDWR,0);
  printf("%d\n",fd);
  write(fd,c,strlen(c));
  close(fd);
  return 0;
}
