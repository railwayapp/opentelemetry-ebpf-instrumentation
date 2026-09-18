// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

enum { k_kprobes_http2_buf_size = 256 };
enum { k_kprobes_http2_ret_buf_size = 64 };

// The incoming-traceparent scan window. Proxies append their headers after the
// client's, so a browser request with cookies pushes traceparent well past 1K;
// 8K matches the usual origin-side header limit.
#define TRACE_BUF_SIZE 8192 // must be power of 2, we do an & to limit the buffer size

_Static_assert((TRACE_BUF_SIZE & (TRACE_BUF_SIZE - 1)) == 0, "TRACE_BUF_SIZE must be a power of 2");
