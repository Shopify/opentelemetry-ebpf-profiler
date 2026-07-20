#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static void stop(int signal_number) {
  (void)signal_number;
  running = 0;
}

int main(void) {
  signal(SIGTERM, stop);
  signal(SIGINT, stop);
  puts("ready");
  fflush(stdout);
  uint64_t iteration = 0;
  while (running) {
    size_t size = (iteration++ % 4096) + 1;
    void *allocation = malloc(size);
    if (allocation == NULL) {
      return 2;
    }
    ((volatile unsigned char *)allocation)[0] = (unsigned char)iteration;
    free(allocation);
    usleep(1000);
  }
  return 0;
}
