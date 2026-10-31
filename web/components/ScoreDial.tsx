"use client";

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";
import { scoreTone } from "@/lib/format";

const COLORS: Record<string, string> = {
  safe: "#9ee37d",
  caution: "#ffc857",
  warn: "#ff5a2b",
  danger: "#ff6b5e",
};

export function ScoreDial({
  score,
  label = "risk score",
  size = 168,
}: {
  score: number;
  label?: string;
  size?: number;
}) {
  const value = Math.max(0, Math.min(100, Math.round(score || 0)));
  const tone = scoreTone(value);
  const color = COLORS[tone] ?? "#9ee37d";
  const radius = 70;
  const circumference = 2 * Math.PI * radius;

  const [shown, setShown] = useState(value);
  const fromRef = useRef(0);
  const boxRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    setShown(0);
  }, []);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setShown(value);
      fromRef.current = value;
      return;
    }
    const el = boxRef.current;
    if (!el) return;

    let raf = 0;
    let started = false;

    const run = () => {
      started = true;
      const from = fromRef.current;
      const start = performance.now();
      const duration = 950;
      const tick = (now: number) => {
        const t = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - t, 4);
        setShown(from + (value - from) * eased);
        if (t < 1) {
          raf = requestAnimationFrame(tick);
        } else {
          fromRef.current = value;
        }
      };
      raf = requestAnimationFrame(tick);
    };

    const io = new IntersectionObserver(
      (entries) => {
        if (started || !entries.some((entry) => entry.isIntersecting)) return;
        io.disconnect();
        run();
      },
      { threshold: 0.35 },
    );
    io.observe(el);

    return () => {
      io.disconnect();
      cancelAnimationFrame(raf);
    };
  }, [value]);

  const dash = (shown / 100) * circumference;

  return (
    <div
      ref={boxRef}
      className={`dial dial-${tone}`}
      style={{ width: size, height: size, "--dial-color": color } as CSSProperties}
      role="img"
      aria-label={`${label}: ${value} out of 100`}
    >
      <svg viewBox="0 0 168 168" aria-hidden="true">
        <circle cx="84" cy="84" r={radius} fill="none" stroke="rgba(243,239,228,0.12)" strokeWidth="2" />
        <circle
          cx="84"
          cy="84"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeDasharray={`${dash} ${circumference - dash}`}
          strokeLinecap="butt"
        />
        <circle cx="84" cy="84" r={radius - 9} fill="none" stroke="rgba(243,239,228,0.07)" strokeWidth="1" />
        <circle
          className="dial-ticks"
          cx="84"
          cy="84"
          r={radius - 18}
          fill="none"
          stroke="rgba(243,239,228,0.2)"
          strokeWidth="1"
          strokeDasharray="1 6"
        />
        {[0, 25, 50, 75, 100].map((tick) => {
          const angle = ((tick / 100) * 360 - 90) * (Math.PI / 180);
          const x1 = 84 + Math.cos(angle) * 78;
          const y1 = 84 + Math.sin(angle) * 78;
          const x2 = 84 + Math.cos(angle) * 82;
          const y2 = 84 + Math.sin(angle) * 82;
          return (
            <line
              key={tick}
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke="rgba(243,239,228,0.3)"
              strokeWidth="1"
            />
          );
        })}
      </svg>
      <div className="dial-center">
        <div className="dial-score" style={{ color }}>
          {Math.round(shown)}
        </div>
        <div className="dial-label">{label}</div>
      </div>
    </div>
  );
}
