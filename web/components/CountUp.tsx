"use client";

import { useEffect, useLayoutEffect, useRef, useState } from "react";

/**
 * Animated integer that counts up the first time it scrolls into view.
 *
 * The server renders the real value so stats stay correct without JS. On the
 * client we reset to zero in a layout effect — before the first paint — and
 * then count up when the element becomes visible.
 */
export function CountUp({
  value,
  duration = 900,
}: {
  value: number;
  duration?: number;
}) {
  const [shown, setShown] = useState(value);
  const ref = useRef<HTMLSpanElement>(null);
  const fromRef = useRef(0);

  useLayoutEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    setShown(0);
  }, []);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setShown(value);
      fromRef.current = value;
      return;
    }

    let raf = 0;
    let started = false;

    const run = () => {
      started = true;
      const from = fromRef.current;
      const start = performance.now();
      const tick = (now: number) => {
        const t = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - t, 3);
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
      { threshold: 0.4 },
    );

    io.observe(el);
    return () => {
      io.disconnect();
      cancelAnimationFrame(raf);
    };
  }, [value, duration]);

  return <span ref={ref}>{Math.round(shown).toLocaleString("en-US")}</span>;
}
