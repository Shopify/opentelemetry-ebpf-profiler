#include <pthread.h>
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

static void *allocate_repeatedly(void *unused) {
  (void)unused;
  uint64_t iteration = 0;
  while (running) {
    size_t size = (iteration++ % 4096) + 1;
    void *allocation = malloc(size);
    if (allocation == NULL) return (void *)1;
    ((volatile unsigned char *)allocation)[0] = (unsigned char)iteration;
    free(allocation);
    usleep(1000);
  }
  return NULL;
}

int main(void) {
  signal(SIGTERM, stop);
  signal(SIGINT, stop);
  pthread_t worker;
  if (pthread_create(&worker, NULL, allocate_repeatedly, NULL) != 0) return 2;
  puts("ready");
  fflush(stdout);
  while (running) usleep(1000);
  void *worker_result = NULL;
  if (pthread_join(worker, &worker_result) != 0 || worker_result != NULL) return 3;
  return 0;
}
