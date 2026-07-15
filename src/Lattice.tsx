import { useEffect, useRef } from "react";

/** Ambient full-pane lattice field. Node color follows the CSS accent var. */
export default function Lattice({ state }: { state: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current!;
    const ctx = canvas.getContext("2d")!;
    let raf = 0;
    let t = 0;

    const resize = () => {
      canvas.width = canvas.offsetWidth * devicePixelRatio;
      canvas.height = canvas.offsetHeight * devicePixelRatio;
    };
    resize();
    window.addEventListener("resize", resize);

    const accent = () =>
      getComputedStyle(document.documentElement.querySelector(".app") ?? document.body)
        .getPropertyValue("--accent")
        .trim() || "#ff4d5e";

    const draw = () => {
      t += state === "negotiating" ? 0.014 : 0.005;
      const w = canvas.width;
      const h = canvas.height;
      ctx.clearRect(0, 0, w, h);
      const color = accent();
      const cols = 14;
      const rows = 9;
      const pts: [number, number][] = [];
      for (let i = 0; i <= cols; i++) {
        for (let j = 0; j <= rows; j++) {
          const x = (i / cols) * w + Math.sin(t + i * 0.9 + j * 1.3) * 14 * devicePixelRatio;
          const y = (j / rows) * h + Math.cos(t + i * 1.1 + j * 0.7) * 14 * devicePixelRatio;
          pts.push([x, y]);
        }
      }
      ctx.strokeStyle = color;
      ctx.globalAlpha = 0.05;
      ctx.lineWidth = devicePixelRatio;
      for (let i = 0; i <= cols; i++) {
        for (let j = 0; j <= rows; j++) {
          const p = pts[i * (rows + 1) + j];
          if (i < cols) {
            const r = pts[(i + 1) * (rows + 1) + j];
            ctx.beginPath();
            ctx.moveTo(p[0], p[1]);
            ctx.lineTo(r[0], r[1]);
            ctx.stroke();
          }
          if (j < rows) {
            const d = pts[i * (rows + 1) + j + 1];
            ctx.beginPath();
            ctx.moveTo(p[0], p[1]);
            ctx.lineTo(d[0], d[1]);
            ctx.stroke();
          }
        }
      }
      ctx.globalAlpha = 0.14;
      ctx.fillStyle = color;
      for (const [x, y] of pts) {
        ctx.beginPath();
        ctx.arc(x, y, 1.4 * devicePixelRatio, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalAlpha = 1;
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, [state]);

  return <canvas ref={ref} className="lattice" style={{ width: "100%", height: "100%" }} />;
}
