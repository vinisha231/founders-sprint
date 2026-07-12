#!/usr/bin/env node
"use strict";

/* Regenerates grooming-alert-demo.mp4 from scene.html.

   scene.html has NO wall-clock timers — it exposes window.renderAt(ms),
   a pure function of time, so every frame is captured at an exact,
   reproducible moment instead of racing real setTimeout delays.

   One-time local setup (NOT part of the main package.json — Trana's
   detector has zero runtime dependencies; this script is a dev-only
   content-generation utility):
     npm install playwright
     npx playwright install chromium

   Then: node demo/generate-video.mjs
   Requires ffmpeg on PATH (brew install ffmpeg) for the final encode step. */

import { chromium } from "playwright";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const FPS = 20;
const FRAMES_DIR = path.join(DIR, "frames");
const OUT = path.join(DIR, "grooming-alert-demo.mp4");

async function main() {
  fs.rmSync(FRAMES_DIR, { recursive: true, force: true });
  fs.mkdirSync(FRAMES_DIR);

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 760, height: 660 }, deviceScaleFactor: 2 });
  await page.goto("file://" + path.join(DIR, "scene.html"));

  const total = await page.evaluate(() => window.TOTAL_MS);
  const frameMs = 1000 / FPS;
  const frameCount = Math.ceil(total / frameMs) + Math.round(1000 / frameMs); // +1s trailing hold

  for (let i = 0; i < frameCount; i++) {
    const ms = Math.min(i * frameMs, total);
    await page.evaluate((t) => window.renderAt(t), ms);
    await page.screenshot({ path: path.join(FRAMES_DIR, `f${String(i).padStart(5, "0")}.png`) });
  }
  await browser.close();

  execSync(
    `ffmpeg -y -framerate ${FPS} -i "${FRAMES_DIR}/f%05d.png" ` +
    `-vf "pad=ceil(iw/2)*2:ceil(ih/2)*2" -c:v libx264 -pix_fmt yuv420p -crf 18 "${OUT}"`,
    { stdio: "inherit" }
  );

  fs.rmSync(FRAMES_DIR, { recursive: true, force: true });
  console.log("wrote", OUT);
}

main();
