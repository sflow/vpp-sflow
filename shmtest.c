#include <sys/mman.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define SHM_SIZE 2000000
#define SFLOW_SHM_PATH "/vpp-sflow-counters-1"

int
main(int argc, char *argv[])
{
  int fd = shm_open(SFLOW_SHM_PATH, O_RDWR, 0);
  if (fd == -1)
    errExit("shm_open");
  uint64_t *datap = mmap(NULL, SHM_SIZE,
			 PROT_READ | PROT_WRITE,
			 MAP_SHARED, fd, 0);
  if (datap == MAP_FAILED)
    errExit("mmap");
  for(int ii = 0; ii < 32; ii++)
    printf("%u: =%"PRIu64"\n", ii, datap[ii]);
  exit(EXIT_SUCCESS);
}
