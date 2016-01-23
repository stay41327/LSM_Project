#include <stdio.h>

int main()
{
  printf("Reading config File ...\n");
  FILE *fd = fopen("config","r");
  char buf[1024]={0};
  fread(buf,1024,1,fd);
  printf("%s",buf);
  fclose(fd);

  printf("Write config File ...\n");
  fd = fopen("config","a");
  fwrite("test\n",5,1,fd);
  fclose(fd);
  return 0;
}
