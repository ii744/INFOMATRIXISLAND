#!/usr/bin/env node

/**
 * AuraCast Batch Analyzer
 *
 * Provides multi-feature statistical and spectral analysis for detecting
 * AI-generated audio versus authentic human speech.
 *
 * Supported formats: WAV (native), MP3, OGG, FLAC (requires ffmpeg)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

/**
 * ANSI Color codes for terminal output
 */
const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  magenta: '\x1b[35m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

const SUPPORTED_EXTENSIONS = new Set(['.wav', '.mp3', '.ogg', '.flac', '.oga', '.opus']);
const ANALYSIS_WINDOW_SECONDS = 0.4;

const args = process.argv.slice(2);
const isVerbose = args.includes('--verbose') || args.includes('-v');
const pathArgs = args.filter(arg => !arg.startsWith('-'));

if (pathArgs.length === 0) {
  console.log(`${COLORS.yellow}Usage: node analyzer.js [--verbose] <path_to_audio_file_or_folder>${COLORS.reset}`);
  console.log(`${COLORS.dim}Example: node analyzer.js ./my_audio_folder${COLORS.reset}`);
  console.log(`${COLORS.dim}Example: node analyzer.js ./audio.wav${COLORS.reset}`);
  process.exit(1);
}

const targetPath = pathArgs[0];

/**
 * Performs an in-place Radix-2 Cooley-Tukey FFT.
 * @param {Float64Array} real - Real components
 * @param {Float64Array} imag - Imaginary components
 */
function performFFT(real, imag) {
  const n = real.length;

  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      [real[i], real[j]] = [real[j], real[i]];
      [imag[i], imag[j]] = [imag[j], imag[i]];
    }
  }

  for (let len = 2; len <= n; len <<= 1) {
    const halfLen = len >> 1;
    const angle = -2 * Math.PI / len;
    const wReal = Math.cos(angle);
    const wImag = Math.sin(angle);

    for (let i = 0; i < n; i += len) {
      let curReal = 1;
      let curImag = 0;
      for (let j = 0; j < halfLen; j++) {
        const uReal = real[i + j];
        const uImag = imag[i + j];
        const vReal = real[i + j + halfLen] * curReal - imag[i + j + halfLen] * curImag;
        const vImag = real[i + j + halfLen] * curImag + imag[i + j + halfLen] * curReal;

        real[i + j] = uReal + vReal;
        imag[i + j] = uImag + vImag;
        real[i + j + halfLen] = uReal - vReal;
        imag[i + j + halfLen] = uImag - vImag;

        const nextReal = curReal * wReal - curImag * wImag;
        curImag = curReal * wImag + curImag * wReal;
        curReal = nextReal;
      }
    }
  }
}

/**
 * Analyzes audio data to detect AI generation markers.
 * @param {Float32Array} data - Raw audio samples
 * @param {number} sampleRate - Audio sample rate
 * @returns {Object} Analysis results and metadata
 */
function runDetection(data, sampleRate) {
  const duration = data.length / sampleRate;
  const windowSize = Math.floor(sampleRate * ANALYSIS_WINDOW_SECONDS);

  const blocks = [];
  for (let i = 0; i < data.length; i += windowSize) {
    const end = Math.min(i + windowSize, data.length);
    const chunk = data.subarray(i, end);
    if (chunk.length < windowSize * 0.5) continue;

    let zeroCrossings = 0;
    let sumSquares = 0;
    let peakAmplitude = 0;
    let nearZeroSamples = 0;

    for (let j = 0; j < chunk.length; j++) {
      const val = chunk[j];
      const absVal = Math.abs(val);
      sumSquares += val * val;
      if (absVal > peakAmplitude) peakAmplitude = absVal;
      if (absVal < 0.0001) nearZeroSamples++;
      if (j > 0 && ((chunk[j - 1] > 0 && val <= 0) || (chunk[j - 1] < 0 && val >= 0))) {
        zeroCrossings++;
      }
    }

    blocks.push({
      rms: Math.sqrt(sumSquares / chunk.length),
      zcr: zeroCrossings * (sampleRate / chunk.length),
      peak: peakAmplitude,
      nzr: nearZeroSamples / chunk.length,
    });
  }

  if (blocks.length < 5) {
    return createResult('HUMAN', 0, duration, 'Audio segment too short for reliable analysis', {});
  }

  const sortedRms = blocks.map(b => b.rms).sort((a, b) => a - b);
  const p10 = sortedRms[Math.floor(sortedRms.length * 0.1)];
  const speechThreshold = Math.max(p10 * 3, 0.003);
  const speechBlocks = blocks.filter(b => b.rms > speechThreshold);

  if (speechBlocks.length < 3) {
    return createResult('HUMAN', 0, duration, 'Insufficient speech content detected', {});
  }

  const speechRmsValues = speechBlocks.map(b => b.rms);
  const speechZcrValues = speechBlocks.map(b => b.zcr);
  const speechCrestFactors = speechBlocks.map(b => b.rms > 0 ? b.peak / b.rms : 0);

  const energyCV = calculateCV(speechRmsValues);
  const zcrCV = calculateCV(speechZcrValues);
  const crestCV = calculateCV(speechCrestFactors);

  let jumpSum = 0;
  for (let i = 1; i < blocks.length; i++) {
    jumpSum += Math.abs(blocks[i].rms - blocks[i - 1].rms);
  }
  const meanRms = calculateMean(speechRmsValues);
  const dynamics = meanRms > 0 ? (jumpSum / (blocks.length - 1)) / meanRms : 0;

  const FFT_SIZE = 2048;
  const centroids = [];
  const flatnesses = [];
  const hfRatios = [];

  for (let start = 0; start < data.length - FFT_SIZE; start += FFT_SIZE) {
    let frameSumSquares = 0;
    for (let i = 0; i < FFT_SIZE; i++) frameSumSquares += data[start + i] * data[start + i];
    if (Math.sqrt(frameSumSquares / FFT_SIZE) < speechThreshold) continue;

    const real = new Float64Array(FFT_SIZE);
    const imag = new Float64Array(FFT_SIZE);
    for (let i = 0; i < FFT_SIZE; i++) {
      const hann = 0.5 - 0.5 * Math.cos(2 * Math.PI * i / (FFT_SIZE - 1));
      real[i] = data[start + i] * hann;
    }
    performFFT(real, imag);

    const halfSize = FFT_SIZE / 2;
    const magnitude = new Float64Array(halfSize);
    for (let k = 0; k < halfSize; k++) {
      magnitude[k] = Math.sqrt(real[k] * real[k] + imag[k] * imag[k]);
    }

    let sumMag = 0;
    let sumWeightedMag = 0;
    for (let k = 0; k < halfSize; k++) {
      const freq = k * sampleRate / FFT_SIZE;
      sumWeightedMag += freq * magnitude[k];
      sumMag += magnitude[k];
    }
    if (sumMag > 0) centroids.push(sumWeightedMag / sumMag);

    let logSum = 0;
    let linearSum = 0;
    let binCount = 0;
    for (let k = 1; k < halfSize; k++) {
      if (magnitude[k] > 1e-10) {
        logSum += Math.log(magnitude[k]);
        linearSum += magnitude[k];
        binCount++;
      }
    }
    if (binCount > 0 && linearSum > 0) {
      flatnesses.push(Math.exp(logSum / binCount) / (linearSum / binCount));
    }

    const bin4k = Math.floor(4000 * FFT_SIZE / sampleRate);
    let lowEnergy = 0;
    let highEnergy = 0;
    for (let k = 0; k < halfSize; k++) {
      const energy = magnitude[k] * magnitude[k];
      if (k < bin4k) lowEnergy += energy;
      else highEnergy += energy;
    }
    if (lowEnergy + highEnergy > 0) hfRatios.push(highEnergy / (lowEnergy + highEnergy));
  }

  const centroidCV = centroids.length > 1 ? calculateCV(centroids) : 0.5;
  const flatnessMean = calculateMean(flatnesses);
  const flatnessCV = flatnesses.length > 1 ? calculateCV(flatnesses) : 0.5;
  const hfMean = calculateMean(hfRatios);

  const features = { energyCV, zcrCV, crestCV, dynamics, centroidCV, flatnessMean, flatnessCV, hfMean };

  const subScores = {
    lowFlatness: 1 - Math.min(Math.max(flatnessMean / 0.035, 0), 1),
    stableFlatness: 1 - Math.min(Math.max(flatnessCV / 0.70, 0), 1),
    energyFlat: 1 - Math.min(Math.max(energyCV / 0.55, 0), 1),
  };

  const weights = {
    lowFlatness: 0.50,
    stableFlatness: 0.20,
    energyFlat: 0.30,
  };

  let finalScore = 0;
  for (const [key, weight] of Object.entries(weights)) {
    finalScore += (subScores[key] || 0) * weight;
  }

  const verdict = finalScore > 0.30 ? 'AI' : 'HUMAN';

  const indicators = [];
  if (subScores.lowFlatness > 0.4) indicators.push('low spectral flatness');
  if (subScores.stableFlatness > 0.4) indicators.push('uniform spectral profile');
  if (subScores.energyFlat > 0.4) indicators.push('flat energy');
  const details = indicators.length > 0 ? indicators.join(', ') : 'Authentic speech patterns';

  return createResult(verdict, finalScore, duration, details, features, subScores, speechBlocks.length);
}

/**
 * Creates a standardized result object.
 */
function createResult(verdict, score, duration, details, features, scores, speechBlocks) {
  return {
    verdict,
    score,
    duration,
    details,
    features,
    scores: scores || {},
    totalSpeechBlocks: speechBlocks || 0,
  };
}

/**
 * Math utility functions
 */
function calculateMean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((sum, val) => sum + val, 0) / arr.length;
}

function calculateStdDev(arr) {
  if (arr.length < 2) return 0;
  const mean = calculateMean(arr);
  const variance = arr.reduce((sum, val) => sum + (val - mean) ** 2, 0) / (arr.length - 1);
  return Math.sqrt(variance);
}

function calculateCV(arr) {
  const mean = calculateMean(arr);
  return mean > 0 ? calculateStdDev(arr) / mean : 0;
}

/**
 * System utility functions
 */
function checkFfmpegAvailability() {
  try {
    execSync('ffmpeg -version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Recursively scans directory for audio files.
 */
function scanDirectory(dir, hasFfmpeg) {
  const files = [];
  (function walk(currentDir) {
    for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (!entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'results') {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SUPPORTED_EXTENSIONS.has(ext) && (ext === '.wav' || hasFfmpeg)) {
          files.push(fullPath);
        }
      }
    }
  })(dir);
  return files.sort();
}

/**
 * Analyzes a single audio file.
 */
function analyzeFile(filePath, hasFfmpeg) {
  const ext = path.extname(filePath).toLowerCase();
  let samples, sampleRate;

  if (ext === '.wav') {
    const result = parseWav(fs.readFileSync(filePath));
    samples = result.samples;
    sampleRate = result.sampleRate;
  } else {
    if (!hasFfmpeg) throw new Error(`ffmpeg is required to process ${ext} files`);
    const result = convertAndParse(filePath);
    samples = result.samples;
    sampleRate = result.sampleRate;
  }

  return runDetection(samples, sampleRate);
}

/**
 * Parses a standard WAV file.
 */
function parseWav(buffer) {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  if (String.fromCharCode(buffer[0], buffer[1], buffer[2], buffer[3]) !== 'RIFF') {
    throw new Error('Not a valid RIFF file');
  }

  let offset = 12;
  let audioFormat, numChannels, sampleRate, bitsPerSample;
  let formatFound = false;

  while (offset < buffer.length - 8) {
    const chunkId = String.fromCharCode(buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]);
    const chunkSize = view.getUint32(offset + 4, true);

    if (chunkId === 'fmt ') {
      audioFormat = view.getUint16(offset + 8, true);
      numChannels = view.getUint16(offset + 10, true);
      sampleRate = view.getUint32(offset + 12, true);
      bitsPerSample = view.getUint16(offset + 22, true);
      formatFound = true;
    }

    if (chunkId === 'data' && formatFound) {
      const dataOffset = offset + 8;
      const sampleCount = Math.floor(chunkSize / ((bitsPerSample / 8) * numChannels));
      const samples = new Float32Array(sampleCount);

      for (let i = 0; i < sampleCount; i++) {
        const byteOffset = dataOffset + i * numChannels * (bitsPerSample / 8);
        if (byteOffset + (bitsPerSample / 8) > buffer.length) break;

        if (audioFormat === 1) { // PCM
          if (bitsPerSample === 16) samples[i] = view.getInt16(byteOffset, true) / 32768.0;
          else if (bitsPerSample === 24) {
            let val = (buffer[byteOffset + 2] << 16) | (buffer[byteOffset + 1] << 8) | buffer[byteOffset];
            if (val >= 0x800000) val -= 0x1000000;
            samples[i] = val / 8388608.0;
          } else if (bitsPerSample === 32) samples[i] = view.getInt32(byteOffset, true) / 2147483648.0;
        } else if (audioFormat === 3) { // IEEE Float
          samples[i] = view.getFloat32(byteOffset, true);
        }
      }
      return { samples, sampleRate };
    }
    offset += 8 + chunkSize;
    if (chunkSize % 2 !== 0) offset++;
  }
  throw new Error('No data chunk found in WAV file');
}

/**
 * Converts non-WAV formats using ffmpeg.
 */
function convertAndParse(filePath) {
  const tempPath = path.join(os.tmpdir(), `auracast-${Date.now()}.wav`);
  try {
    execSync(`ffmpeg -y -i "${filePath}" -ac 1 -ar 44100 -sample_fmt s16 "${tempPath}" 2>/dev/null`, {
      stdio: 'pipe',
      timeout: 60000,
    });
    return parseWav(fs.readFileSync(tempPath));
  } finally {
    try { fs.unlinkSync(tempPath); } catch (e) { /* ignore cleanup errors */ }
  }
}

/**
 * Main execution entry point.
 */
function main() {
  console.log(`\n${COLORS.bold}${COLORS.magenta}  AuraCast Batch Analyzer${COLORS.reset}\n`);

  const hasFfmpeg = checkFfmpegAvailability();
  if (!hasFfmpeg) {
    console.log(`${COLORS.yellow}  [Note] ffmpeg not found. Only WAV files are supported.${COLORS.reset}\n`);
  }

  const absolutePath = path.resolve(targetPath);
  if (!fs.existsSync(absolutePath)) {
    console.error(`${COLORS.red}  Error: Path not found at ${absolutePath}${COLORS.reset}`);
    process.exit(1);
  }

  const stat = fs.statSync(absolutePath);
  const files = stat.isFile() ? [absolutePath] : scanDirectory(absolutePath, hasFfmpeg);

  if (!files.length) {
    console.log(`${COLORS.yellow}  No supported audio files found.${COLORS.reset}`);
    process.exit(0);
  }

  console.log(`${COLORS.cyan}  Found ${files.length} audio file(s)${COLORS.reset}\n`);

  const results = [];
  for (let i = 0; i < files.length; i++) {
    const filePath = files[i];
    const relativeName = path.relative(absolutePath, filePath) || path.basename(filePath);

    process.stdout.write(`  ${COLORS.dim}[${i + 1}/${files.length}]${COLORS.reset} ${COLORS.white}${relativeName}${COLORS.reset} `);

    try {
      const result = analyzeFile(filePath, hasFfmpeg);
      result.file = relativeName;
      results.push(result);

      const label = result.verdict === 'AI'
        ? `${COLORS.bgRed}${COLORS.white}${COLORS.bold} AI ${COLORS.reset}`
        : `${COLORS.bgGreen}${COLORS.white}${COLORS.bold} HUMAN ${COLORS.reset}`;

      console.log(`${label} ${COLORS.dim}(${(result.score * 100).toFixed(1)}%)${COLORS.reset}`);

      if (isVerbose && result.features) {
        const { features: f, scores: s } = result;
        console.log(`    ${COLORS.dim}Features: flatMean=${f.flatnessMean?.toFixed(4)} flatCV=${f.flatnessCV?.toFixed(3)} eCV=${f.energyCV?.toFixed(3)} zCV=${f.zcrCV?.toFixed(3)}`);
        console.log(`    Scores:   lowFlat=${s.lowFlatness?.toFixed(2)} stableFlat=${s.stableFlatness?.toFixed(2)} eFlat=${s.energyFlat?.toFixed(2)} → total=${result.score.toFixed(3)}${COLORS.reset}`);
      }
    } catch (err) {
      console.log(`${COLORS.red}ERROR: ${err.message}${COLORS.reset}`);
      results.push({ file: relativeName, verdict: 'ERROR', score: 0, error: err.message });
    }
  }

  console.log('');
  displayTable(results);
  displaySummary(results);
  exportReport(results, absolutePath);
}

/**
 * Formats and displays the results table.
 */
function displayTable(results) {
  const fileNameWidth = Math.max(20, ...results.map(r => r.file.length)) + 2;
  const separator = '─'.repeat(fileNameWidth + 55);

  console.log(`${COLORS.dim}${separator}${COLORS.reset}`);
  console.log(`${COLORS.bold}  ${'File'.padEnd(fileNameWidth)}${'Verdict'.padEnd(10)}${'Score'.padEnd(10)}${'Duration'.padEnd(10)}Details${COLORS.reset}`);
  console.log(`${COLORS.dim}${separator}${COLORS.reset}`);

  for (const r of results) {
    const scoreText = r.verdict === 'ERROR' ? '—' : `${(r.score * 100).toFixed(1)}%`;
    const durationText = r.duration ? formatDuration(r.duration) : '—';
    const detailText = (r.details || r.error || '').substring(0, 40);

    let verdictLabel;
    if (r.verdict === 'AI') verdictLabel = `${COLORS.red}${COLORS.bold}AI${COLORS.reset}`.padEnd(19);
    else if (r.verdict === 'HUMAN') verdictLabel = `${COLORS.green}${COLORS.bold}HUMAN${COLORS.reset}`.padEnd(19);
    else verdictLabel = `${COLORS.yellow}ERROR${COLORS.reset}`.padEnd(19);

    console.log(`  ${COLORS.white}${r.file.padEnd(fileNameWidth)}${COLORS.reset}${verdictLabel}${scoreText.padEnd(10)}${durationText.padEnd(10)}${COLORS.dim}${detailText}${COLORS.reset}`);
  }
  console.log(`${COLORS.dim}${separator}${COLORS.reset}`);
}

/**
 * Displays summary statistics by folder.
 */
function displaySummary(results) {
  console.log(`\n${COLORS.bold}${COLORS.cyan}  Summary Statistics${COLORS.reset}\n`);

  const groups = {};
  for (const r of results) {
    if (r.verdict === 'ERROR') continue;
    const folder = path.dirname(r.file);
    if (!groups[folder]) groups[folder] = { total: 0, aiCount: 0, humanCount: 0 };
    groups[folder].total++;
    if (r.verdict === 'AI') groups[folder].aiCount++;
    else groups[folder].humanCount++;
  }

  for (const [folder, g] of Object.entries(groups)) {
    let folderDisplay = folder === '.' ? 'Selected File(s)' : `${folder}/`;
    console.log(`  📁 ${COLORS.white}${folderDisplay}${COLORS.reset} | Total: ${g.total} | Human: ${COLORS.green}${g.humanCount}${COLORS.reset} | AI: ${COLORS.red}${g.aiCount}${COLORS.reset}\n`);
  }

  const validResults = results.filter(r => r.verdict !== 'ERROR');
  console.log(`  ${COLORS.dim}──────────────────────────────────${COLORS.reset}`);
  console.log(`  Total Scanned:  ${validResults.length}`);
  console.log(`  AI Detected:    ${COLORS.red}${validResults.filter(r => r.verdict === 'AI').length}${COLORS.reset}`);
  console.log(`  Human Detected: ${COLORS.green}${validResults.filter(r => r.verdict === 'HUMAN').length}${COLORS.reset}`);

  const errorCount = results.filter(r => r.verdict === 'ERROR').length;
  if (errorCount) console.log(`  Errors encountered: ${COLORS.yellow}${errorCount}${COLORS.reset}`);
  console.log('');
}

/**
 * Saves analysis results to a JSON report.
 */
function exportReport(results, basePath) {
  const outputDir = path.join(__dirname, 'results');
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportPath = path.join(outputDir, `report-${timestamp}.json`);

  const reportData = {
    timestamp: new Date().toISOString(),
    basePath,
    totalFiles: results.length,
    results: results.map(r => ({
      file: r.file,
      verdict: r.verdict,
      score: r.score,
      duration: r.duration,
      details: r.details,
      features: r.features,
      scores: r.scores,
    })),
  };

  fs.writeFileSync(reportPath, JSON.stringify(reportData, null, 2));
  console.log(`${COLORS.dim}  Report generated: ${reportPath}${COLORS.reset}\n`);
}

/**
 * Helper to format duration in seconds to M:S.
 */
function formatDuration(seconds) {
  const m = Math.floor(seconds / 60);
  const s = (seconds % 60).toFixed(1);
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

main();
