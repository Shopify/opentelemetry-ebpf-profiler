// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// A minimal shared object whose calls go through the PLT. See plt-arm64.so in
// the Makefile and TestARM64PLTDeltas.
#include <stdlib.h>
#include <string.h>

void *plt_test_copy(const void *src, size_t n)
{
  void *dst = malloc(n);
  return dst ? memcpy(dst, src, n) : NULL;
}
