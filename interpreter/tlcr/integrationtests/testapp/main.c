// TLCR integration test binary.
//
// Writes known trace_id (all 0x42) and span_id (all 0xAB) into the TLCR
// TLS variable, then burns CPU in a loop so the eBPF profiler can sample it.
//
// Build:
//   gcc -O2 -o tlcr_testapp main.c -lpthread

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

// TLCR record layout (28 bytes, matching custom_labels_v2_tl_record_t)
typedef struct __attribute__((packed)) {
    uint8_t trace_id[16];
    uint8_t span_id[8];
    uint8_t valid;
    uint8_t _padding;
    uint16_t attrs_data_size;
} tlcr_record_t;

// The TLS variable the eBPF profiler scans for
__attribute__((retain))
__thread tlcr_record_t *custom_labels_current_set_v2 = NULL;

static volatile sig_atomic_t running = 1;

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

// Burn CPU so the profiler can sample us
static volatile uint64_t sink = 0;
__attribute__((noinline))
static void burn_cpu(void) {
    for (int i = 0; i < 1000000 && running; i++) {
        sink += (uint64_t)i * 7 + 13;
    }
}

int main(void) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    // Allocate and populate TLCR record
    tlcr_record_t *record = calloc(1, sizeof(tlcr_record_t));
    if (!record) {
        fprintf(stderr, "Failed to allocate TLCR record\n");
        return 1;
    }

    // Known trace_id: all 0x42
    memset(record->trace_id, 0x42, 16);
    // Known span_id: all 0xAB
    memset(record->span_id, 0xAB, 8);
    record->valid = 1;
    record->attrs_data_size = 0;

    // Set as current TLCR record with memory barrier
    atomic_thread_fence(memory_order_seq_cst);
    custom_labels_current_set_v2 = record;
    atomic_thread_fence(memory_order_seq_cst);

    fprintf(stderr, "TLCR test app running (pid=%d), trace_id=0x42..., span_id=0xAB...\n",
            getpid());

    // Burn CPU until killed
    while (running) {
        burn_cpu();
        usleep(1000); // 1ms sleep between burns
    }

    fprintf(stderr, "TLCR test app exiting\n");
    free(record);
    return 0;
}
