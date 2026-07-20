#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef RESOLVE_ALLOCATORS
static void *(*target_malloc)(size_t);
static void (*target_free)(void *);

static int resolve_allocators(void) {
  target_malloc = (void *(*)(size_t))dlsym(RTLD_DEFAULT, "malloc");
  target_free = (void (*)(void *))dlsym(RTLD_DEFAULT, "free");
  return target_malloc != NULL && target_free != NULL ? 0 : -1;
}
#else
#define target_malloc malloc
#define target_free free
static int resolve_allocators(void) { return 0; }
#endif

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
    void *allocation = target_malloc(size);
    if (allocation == NULL) return (void *)1;
    ((volatile unsigned char *)allocation)[0] = (unsigned char)iteration;
    target_free(allocation);
    usleep(1000);
  }
  return NULL;
}

int main(void) {
  signal(SIGTERM, stop);
  signal(SIGINT, stop);
  if (resolve_allocators() != 0) return 4;
  pthread_t worker;
  if (pthread_create(&worker, NULL, allocate_repeatedly, NULL) != 0) return 2;
  puts("ready");
  fflush(stdout);
  while (running) usleep(1000);
  void *worker_result = NULL;
  if (pthread_join(worker, &worker_result) != 0 || worker_result != NULL) return 3;
  return 0;
}
