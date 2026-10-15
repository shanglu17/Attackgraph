import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

const startedAt = new Date().toISOString();
let requestCount = 0;
let errorCount = 0;
let inFlight = 0;
const durations: number[] = [];
const statusCounts = new Map<string, number>();

function percentile(values: number[], ratio: number): number {
  if (values.length === 0) return 0;
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.min(ordered.length - 1, Math.ceil(ordered.length * ratio) - 1)];
}

export function requestMetricsSnapshot() {
  return {
    started_at: startedAt,
    requests_total: requestCount,
    errors_total: errorCount,
    in_flight: inFlight,
    latency_ms: {
      p50: Number(percentile(durations, 0.5).toFixed(2)),
      p95: Number(percentile(durations, 0.95).toFixed(2)),
      max: Number((durations.length === 0 ? 0 : Math.max(...durations)).toFixed(2)),
    },
    responses_by_status: Object.fromEntries([...statusCounts.entries()].sort()),
  };
}

export function observeRequests(log: (entry: Record<string, unknown>) => void = (entry) => console.log(JSON.stringify(entry))) {
  return (request: Request, response: Response, next: NextFunction) => {
    const requestedId = request.header("x-request-id")?.trim();
    const requestId = requestedId && /^[A-Za-z0-9._:-]{1,160}$/.test(requestedId) ? requestedId : randomUUID();
    const start = performance.now();
    requestCount += 1;
    inFlight += 1;
    response.setHeader("X-Request-Id", requestId);
    response.once("finish", () => {
      inFlight -= 1;
      const durationMs = performance.now() - start;
      durations.push(durationMs);
      if (durations.length > 2_000) durations.splice(0, durations.length - 2_000);
      const family = `${Math.floor(response.statusCode / 100)}xx`;
      statusCounts.set(family, (statusCounts.get(family) ?? 0) + 1);
      if (response.statusCode >= 500) errorCount += 1;
      log({
        event: "http_request_completed",
        request_id: requestId,
        method: request.method,
        path: request.path,
        status: response.statusCode,
        duration_ms: Number(durationMs.toFixed(2)),
      });
    });
    next();
  };
}
