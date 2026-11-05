import { Paper, Text } from '@mantine/core';
import { useElementSize } from '@mantine/hooks';
import { useState, type PointerEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { formatTime } from '../ui';

const HEIGHT = 130;
const MARGIN = { top: 8, right: 8, bottom: 20, left: 40 };
// A gap of more than this many steps means the device was off, which the line
// must not bridge.
const MAX_GAP_STEPS = 2.5;

export interface Point {
  ts: number;
  value: number;
}

interface Props {
  title: string;
  points: Point[];
  step: number;
  /** Start of the visible range, in seconds. */
  since: number;
  until: number;
  /** Upper end of the axis. Without it, the data decides. */
  max?: number;
  /** Draws a line at a value, for a warning level. */
  limit?: number;
  format: (value: number) => string;
}

function segments(points: Point[], step: number): Point[][] {
  const parts: Point[][] = [];
  points.forEach((point, i) => {
    if (i === 0 || point.ts - points[i - 1].ts > step * MAX_GAP_STEPS) parts.push([]);
    parts[parts.length - 1].push(point);
  });
  return parts;
}

/** A single series over time, with a crosshair that snaps to the nearest value. */
export function HistoryChart({ title, points, step, since, until, max, limit, format }: Props) {
  const { t } = useTranslation();
  const { ref, width } = useElementSize();
  const [hover, setHover] = useState<Point>();

  const top = max ?? Math.max(...points.map((p) => p.value), 1) * 1.1;
  const plotWidth = Math.max(width - MARGIN.left - MARGIN.right, 1);
  const plotHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
  const x = (ts: number) => MARGIN.left + ((ts - since) / (until - since)) * plotWidth;
  const y = (value: number) => MARGIN.top + (1 - Math.min(value / top, 1)) * plotHeight;
  const line = (part: Point[]) =>
    part.map((p, i) => `${i ? 'L' : 'M'}${x(p.ts).toFixed(1)} ${y(p.value).toFixed(1)}`).join(' ');

  function track(e: PointerEvent<SVGSVGElement>) {
    const left = e.currentTarget.getBoundingClientRect().left;
    const ts = since + ((e.clientX - left - MARGIN.left) / plotWidth) * (until - since);
    setHover(
      points.reduce<Point | undefined>(
        (best, p) => (!best || Math.abs(p.ts - ts) < Math.abs(best.ts - ts) ? p : best),
        undefined,
      ),
    );
  }

  const values = points.map((p) => p.value);
  const summary = points.length
    ? t('insight.chartSummary', {
        title,
        min: format(Math.min(...values)),
        max: format(Math.max(...values)),
        last: format(values[values.length - 1]),
      })
    : t('insight.noHistory');
  const flipTooltip = hover !== undefined && x(hover.ts) > width / 2;

  return (
    <div>
      <Text size="sm" fw={500}>
        {title}
      </Text>
      <div ref={ref} style={{ position: 'relative', height: HEIGHT }}>
        {width > 0 && (
          <svg
            width={width}
            height={HEIGHT}
            role="img"
            aria-label={summary}
            onPointerMove={track}
            onPointerLeave={() => setHover(undefined)}
          >
            {[0, 0.5, 1].map((share) => (
              <g key={share}>
                <line
                  x1={MARGIN.left}
                  x2={width - MARGIN.right}
                  y1={y(top * share)}
                  y2={y(top * share)}
                  stroke="var(--mantine-color-default-border)"
                />
                <text
                  x={MARGIN.left - 6}
                  y={y(top * share) + 4}
                  textAnchor="end"
                  fontSize={11}
                  fill="var(--mantine-color-dimmed)"
                >
                  {format(top * share)}
                </text>
              </g>
            ))}
            {limit !== undefined && (
              <line
                x1={MARGIN.left}
                x2={width - MARGIN.right}
                y1={y(limit)}
                y2={y(limit)}
                stroke="var(--mantine-color-red-6)"
                strokeDasharray="4 4"
              />
            )}
            {[since, until].map((ts, i) => (
              <text
                key={ts}
                x={x(ts)}
                y={HEIGHT - 5}
                textAnchor={i ? 'end' : 'start'}
                fontSize={11}
                fill="var(--mantine-color-dimmed)"
              >
                {formatTime(ts)}
              </text>
            ))}
            {segments(points, step).map((part) =>
              part.length > 1 ? (
                <path
                  key={part[0].ts}
                  d={line(part)}
                  fill="none"
                  stroke="var(--mantine-color-blue-6)"
                  strokeWidth={2}
                  strokeLinejoin="round"
                  strokeLinecap="round"
                />
              ) : (
                <circle key={part[0].ts} cx={x(part[0].ts)} cy={y(part[0].value)} r={2.5} fill="var(--mantine-color-blue-6)" />
              ),
            )}
            {hover && (
              <>
                <line
                  x1={x(hover.ts)}
                  x2={x(hover.ts)}
                  y1={MARGIN.top}
                  y2={HEIGHT - MARGIN.bottom}
                  stroke="var(--mantine-color-dimmed)"
                />
                <circle
                  cx={x(hover.ts)}
                  cy={y(hover.value)}
                  r={4}
                  fill="var(--mantine-color-blue-6)"
                  stroke="var(--mantine-color-body)"
                  strokeWidth={2}
                />
              </>
            )}
          </svg>
        )}
        {hover && (
          <Paper
            withBorder
            shadow="xs"
            px="xs"
            py={2}
            style={{
              position: 'absolute',
              top: 0,
              pointerEvents: 'none',
              ...(flipTooltip ? { right: width - x(hover.ts) + 8 } : { left: x(hover.ts) + 8 }),
            }}
          >
            <Text size="xs" fw={500}>
              {format(hover.value)}
            </Text>
            <Text size="xs" c="dimmed">
              {formatTime(hover.ts)}
            </Text>
          </Paper>
        )}
        {points.length === 0 && (
          <Text
            size="sm"
            c="dimmed"
            ta="center"
            style={{ position: 'absolute', top: HEIGHT / 2 - 20, left: 0, right: 0 }}
          >
            {t('insight.noHistory')}
          </Text>
        )}
      </div>
    </div>
  );
}
