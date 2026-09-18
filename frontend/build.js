// Wizard Frontend Production Build Script
// Zero-dependency bundler optimized for Android/Termux and Debian proot environments
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SRC_DIR = path.join(__dirname, "src");
const DIST_DIR = path.join(__dirname, "dist");

console.log("=== Building Wizard Frontend ===");
console.log(`Source Directory: ${SRC_DIR}`);
console.log(`Dist Directory:   ${DIST_DIR}`);

// 1. Ensure dist and subdirectories exist
if (fs.existsSync(DIST_DIR)) {
  fs.rmSync(DIST_DIR, { recursive: true, force: true });
}
fs.mkdirSync(DIST_DIR, { recursive: true });
fs.mkdirSync(path.join(DIST_DIR, "services"), { recursive: true });
fs.mkdirSync(path.join(DIST_DIR, "styles"), { recursive: true });

// 2. Copy and optimize styles
const cssContent = fs.readFileSync(path.join(SRC_DIR, "styles", "main.css"), "utf-8");
fs.writeFileSync(path.join(DIST_DIR, "styles", "main.css"), cssContent, "utf-8");

// 3. Copy modules
const apiContent = fs.readFileSync(path.join(SRC_DIR, "services", "api.js"), "utf-8");
fs.writeFileSync(path.join(DIST_DIR, "services", "api.js"), apiContent, "utf-8");

const appContent = fs.readFileSync(path.join(SRC_DIR, "app.js"), "utf-8");
fs.writeFileSync(path.join(DIST_DIR, "app.js"), appContent, "utf-8");

// 4. Generate production HTML entrypoint
const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WIZARD - AI Cybersecurity Research Platform</title>
  <link rel="stylesheet" href="./styles/main.css">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>⚡</text></svg>">
</head>
<body>
  <div id="app"></div>
  <script type="module" src="./app.js"></script>
</body>
</html>
`;

fs.writeFileSync(path.join(DIST_DIR, "index.html"), htmlContent, "utf-8");

console.log("Assets built successfully:");
const distFiles = fs.readdirSync(DIST_DIR, { recursive: true });
distFiles.forEach((file) => {
  const fullPath = path.join(DIST_DIR, file);
  if (fs.statSync(fullPath).isFile()) {
    const size = (fs.statSync(fullPath).size / 1024).toFixed(2);
    console.log(`  - dist/${file} (${size} KB)`);
  }
});

console.log("✓ Frontend build completed successfully.");
