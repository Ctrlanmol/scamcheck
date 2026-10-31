"use client";

import { useLayoutEffect } from "react";

/**
 * Global motion controller.
 *
 * One client component, mounted once by the shell, is responsible for every
 * ambient effect that would otherwise need per-page wiring:
 *
 *  - scroll reveals for sections, cards, stats, findings and docs prose
 *  - pointer spotlight + a very small tilt on cards
 *  - a pointer-following glow on the home hero
 *  - a reading-progress rail on documentation pages
 *
 * Everything is progressive: without JS the page is fully visible, and with
 * `prefers-reduced-motion` only the functional reading rail is enabled.
 */

const REVEAL_SELECTOR = [
  ".hero-copy > *",
  ".hero-side > *",
  ".page-head .head-copy > *",
  ".page-meta > *",
  ".section-head",
  ".section > .grid > *",
  ".section > .split > *",
  ".section > .stack > *",
  ".section > .card",
  ".section > .table-wrap",
  ".section > .stage-list",
  ".section > .note",
  ".section > .empty",
  ".section > .error",
  ".section > .tabs",
  ".docs-body > *",
  ".finding",
  ".lan-device",
  ".reason",
  ".intel-block",
  ".quick-check",
  ".chat",
  ".ticker",
].join(",");

const POINTER_SELECTOR =
  ".card, .tool-card, .stat, .quick-check, .finding, .lan-device, .hero";

function revealVariant(el: Element): string {
  if (el.matches("h1, h2, h3, .page-index, .display")) return "mask";
  if (el.matches(".stat, .tool-card, .card, .finding, .lan-device, .quick-check")) {
    return "rise";
  }
  if (el.matches(".hero-stat, .page-meta > *")) return "side";
  return "up";
}

export function Motion() {
  useLayoutEffect(() => {
    const root = document.documentElement;
    const main = document.querySelector<HTMLElement>("main.main") ?? document.body;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const tagged = new WeakSet<Element>();
    /*
     * Masked elements clip themselves down to a thin strip before revealing.
     * Chrome factors that clip into the intersection rect, so a 6% threshold
     * would never be reached and the heading would stay invisible forever.
     * Masked targets therefore reveal on any intersection; everything else
     * still waits until roughly a tenth of it is on screen.
     */
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          const masked = entry.target.getAttribute("data-reveal") === "mask";
          const enough = masked ? entry.isIntersecting : entry.intersectionRatio >= 0.08;
          if (!enough) continue;
          entry.target.classList.add("is-revealed");
          observer.unobserve(entry.target);
        }
      },
      { rootMargin: "0px 0px -7% 0px", threshold: [0, 0.08] },
    );

    const tag = (el: Element) => {
      if (!(el instanceof HTMLElement)) return;
      if (tagged.has(el)) return;
      tagged.add(el);
      if (!el.hasAttribute("data-reveal")) {
        el.setAttribute("data-reveal", revealVariant(el));
        const parent = el.parentElement;
        if (parent) {
          const siblings = Array.from(parent.children).filter((child) =>
            child.hasAttribute("data-reveal"),
          );
          const index = Math.max(0, siblings.indexOf(el));
          el.style.setProperty("--reveal-delay", `${Math.min(index, 7) * 55}ms`);
        }
      }
      if (el.getAttribute("data-reveal") !== "none") observer.observe(el);
    };

    if (!reduced) {
      main.querySelectorAll(REVEAL_SELECTOR).forEach(tag);
      root.classList.add("motion-ready");
    }

    /* ---------------------------------------------------------- pointer fx */
    let frame = 0;
    let pending: PointerEvent | null = null;
    let active: HTMLElement | null = null;

    const clearActive = () => {
      if (!active) return;
      active.classList.remove("is-pointer");
      active.style.removeProperty("--rx");
      active.style.removeProperty("--ry");
      active = null;
    };

    const applyPointer = () => {
      frame = 0;
      const event = pending;
      pending = null;
      if (!event) return;
      const target = (event.target as Element | null)?.closest?.(
        POINTER_SELECTOR,
      ) as HTMLElement | null;
      if (active && active !== target) clearActive();
      if (!target) return;
      active = target;
      const rect = target.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      target.style.setProperty("--mx", `${x.toFixed(1)}px`);
      target.style.setProperty("--my", `${y.toFixed(1)}px`);
      target.classList.add("is-pointer");
      if (target.classList.contains("tool-card")) {
        target.style.setProperty("--rx", `${(((y / rect.height) - 0.5) * -3.2).toFixed(2)}deg`);
        target.style.setProperty("--ry", `${(((x / rect.width) - 0.5) * 3.2).toFixed(2)}deg`);
      }
    };

    const onPointerMove = (event: PointerEvent) => {
      if (reduced) return;
      pending = event;
      if (frame) return;
      frame = requestAnimationFrame(applyPointer);
    };

    const onPointerLeave = () => clearActive();

    if (!reduced) {
      main.addEventListener("pointermove", onPointerMove, { passive: true });
      main.addEventListener("pointerleave", onPointerLeave);
      window.addEventListener("blur", onPointerLeave);
    }

    /* ------------------------------------------------------- docs progress */
    let docsEl: HTMLElement | null = null;
    let docsFrame = 0;

    const paintProgress = () => {
      docsFrame = 0;
      if (!docsEl) return;
      const rect = docsEl.getBoundingClientRect();
      const total = rect.height - window.innerHeight + 220;
      const progress = total > 0 ? Math.min(1, Math.max(0, -rect.top / total)) : 1;
      root.style.setProperty("--read-progress", `${(progress * 100).toFixed(2)}%`);
    };

    const onDocsScroll = () => {
      if (docsFrame) return;
      docsFrame = requestAnimationFrame(paintProgress);
    };

    const syncDocs = () => {
      const next = main.querySelector<HTMLElement>(".docs-body");
      if (next === docsEl) return;
      if (docsEl) {
        window.removeEventListener("scroll", onDocsScroll);
        window.removeEventListener("resize", onDocsScroll);
      }
      docsEl = next;
      if (docsEl) {
        root.classList.add("docs-mode");
        window.addEventListener("scroll", onDocsScroll, { passive: true });
        window.addEventListener("resize", onDocsScroll);
        paintProgress();
      } else {
        root.classList.remove("docs-mode");
        root.style.removeProperty("--read-progress");
      }
    };

    syncDocs();

    /* --------------------------------------------------- dynamic content */
    const mutations = new MutationObserver((records) => {
      let sawNode = false;
      for (const record of records) {
        record.addedNodes.forEach((node) => {
          if (!(node instanceof Element)) return;
          sawNode = true;
          if (!reduced) {
            if (node.matches(REVEAL_SELECTOR)) tag(node);
            node.querySelectorAll(REVEAL_SELECTOR).forEach(tag);
          }
        });
      }
      if (sawNode) syncDocs();
    });

    mutations.observe(main, { childList: true, subtree: true });

    return () => {
      observer.disconnect();
      mutations.disconnect();
      clearActive();
      if (frame) cancelAnimationFrame(frame);
      if (docsFrame) cancelAnimationFrame(docsFrame);
      main.removeEventListener("pointermove", onPointerMove);
      main.removeEventListener("pointerleave", onPointerLeave);
      window.removeEventListener("blur", onPointerLeave);
      window.removeEventListener("scroll", onDocsScroll);
      window.removeEventListener("resize", onDocsScroll);
      root.classList.remove("motion-ready", "docs-mode");
      root.style.removeProperty("--read-progress");
    };
  }, []);

  return <div className="read-progress" aria-hidden="true" />;
}
