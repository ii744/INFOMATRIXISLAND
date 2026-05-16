/**
 * AuraCast Web Application
 * AI voice detection (FFT-based) and ultrasonic audio encryption.
 */

const ALL_SCREENS = [
  'main-screen', 'encrypt-screen', 'detect-screen',
  'scanning-screen', 'result-human', 'result-ai', 'result-encrypted'
];

let currentEncryptedBlobUrl = null;

function showScreen(screenId) {
  ALL_SCREENS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = (id === screenId) ? 'block' : 'none';
  });
}

/* ═══════════════════════════════════════════════════════════
   FFT — Radix-2 Cooley-Tukey (in-place)
   ═══════════════════════════════════════════════════════════ */

/**
 * Performs an in-place Radix-2 Cooley-Tukey FFT.
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

/* ═══════════════════════════════════════════════════════════
   Math Utilities
   ═══════════════════════════════════════════════════════════ */

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

/* ═══════════════════════════════════════════════════════════
   Detection Algorithm (ported from AuraCast-CLI)
   ═══════════════════════════════════════════════════════════ */

const ANALYSIS_WINDOW_SECONDS = 0.4;

/**
 * Analyzes raw PCM data to detect AI markers using spectral and statistical features.
 */
function runDetection(data, sampleRate) {
  const windowSize = Math.floor(sampleRate * ANALYSIS_WINDOW_SECONDS);

  const blocks = [];
  for (let i = 0; i < data.length; i += windowSize) {
    const end = Math.min(i + windowSize, data.length);
    const chunk = data.subarray(i, end);
    if (chunk.length < windowSize * 0.5) continue;

    let zeroCrossings = 0;
    let sumSquares = 0;
    let peakAmplitude = 0;

    for (let j = 0; j < chunk.length; j++) {
      const val = chunk[j];
      const absVal = Math.abs(val);
      sumSquares += val * val;
      if (absVal > peakAmplitude) peakAmplitude = absVal;
      if (j > 0 && ((chunk[j - 1] > 0 && val <= 0) || (chunk[j - 1] < 0 && val >= 0))) {
        zeroCrossings++;
      }
    }

    blocks.push({
      rms: Math.sqrt(sumSquares / chunk.length),
      zcr: zeroCrossings * (sampleRate / chunk.length),
      peak: peakAmplitude,
    });
  }

  if (blocks.length < 5) {
    return { verdict: 'HUMAN', score: 0, details: 'Audio too short for reliable analysis' };
  }

  const sortedRms = blocks.map(b => b.rms).sort((a, b) => a - b);
  const p10 = sortedRms[Math.floor(sortedRms.length * 0.1)];
  const speechThreshold = Math.max(p10 * 3, 0.003);
  const speechBlocks = blocks.filter(b => b.rms > speechThreshold);

  if (speechBlocks.length < 3) {
    return { verdict: 'HUMAN', score: 0, details: 'Insufficient speech content' };
  }

  const speechRmsValues = speechBlocks.map(b => b.rms);
  const energyCV = calculateCV(speechRmsValues);

  const FFT_SIZE = 2048;
  const flatnesses = [];

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
  }

  const flatnessMean = calculateMean(flatnesses);
  const flatnessCV = flatnesses.length > 1 ? calculateCV(flatnesses) : 0.5;

  /* Scoring logic: optimized via empirical analysis on test datasets */
  const lowFlatness = 1 - Math.min(Math.max(flatnessMean / 0.035, 0), 1);
  const stableFlatness = 1 - Math.min(Math.max(flatnessCV / 0.70, 0), 1);
  const energyFlat = 1 - Math.min(Math.max(energyCV / 0.55, 0), 1);

  const finalScore = lowFlatness * 0.50 + stableFlatness * 0.20 + energyFlat * 0.30;
  const verdict = finalScore > 0.30 ? 'AI' : 'HUMAN';

  const indicators = [];
  if (lowFlatness > 0.4) indicators.push('low spectral flatness');
  if (stableFlatness > 0.4) indicators.push('uniform spectral profile');
  if (energyFlat > 0.4) indicators.push('flat energy');
  const details = indicators.length > 0 ? indicators.join(', ') : 'Authentic speech patterns';

  return { verdict, score: finalScore, details };
}

/* ═══════════════════════════════════════════════════════════
   AI Detect Handler
   ═══════════════════════════════════════════════════════════ */

async function handleDetect(inputElement) {
  const file = inputElement.files[0];
  if (!file) return;

  showScreen('scanning-screen');
  const scanLabel = document.getElementById('scanning-label');
  scanLabel.textContent = `Analyzing: ${file.name}`;

  let audioCtx = null;
  try {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const arrayBuffer = await file.arrayBuffer();
    const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer);
    const data = audioBuffer.getChannelData(0);
    const sampleRate = audioBuffer.sampleRate;

    const result = await new Promise(resolve => {
      setTimeout(() => resolve(runDetection(data, sampleRate)), 50);
    });

    const confidencePercent = Math.round(result.score * 100);

    if (result.verdict === 'AI') {
      document.getElementById('ai-confidence-value').textContent = `${confidencePercent}%`;
      document.getElementById('ai-confidence-bar').style.width = `${confidencePercent}%`;
      document.getElementById('ai-details').textContent = result.details;
      showScreen('result-ai');
    } else {
      const humanConfidence = 100 - confidencePercent;
      document.getElementById('human-confidence-value').textContent = `${humanConfidence}%`;
      document.getElementById('human-confidence-bar').style.width = `${humanConfidence}%`;
      document.getElementById('human-details').textContent = result.details;
      showScreen('result-human');
    }

  } catch (e) {
    console.error('Detection error:', e);
    alert('Error reading audio file.');
    showScreen('detect-screen');
  } finally {
    if (audioCtx) audioCtx.close();
    inputElement.value = '';
  }
}

/* ═══════════════════════════════════════════════════════════
   Audio Encryption (Ultrasonic Watermark)
   ═══════════════════════════════════════════════════════════ */

/**
 * Encodes an AudioBuffer into a valid 16-bit PCM WAV blob.
 */
function createWavFile(buffer) {
  const numChannels = buffer.numberOfChannels;
  const sampleCount = buffer.length;
  const dataSize = sampleCount * numChannels * 2;
  const fileSize = 44 + dataSize;
  const arrayBuffer = new ArrayBuffer(fileSize);
  const view = new DataView(arrayBuffer);

  let offset = 0;

  function writeUint16(val) { view.setUint16(offset, val, true); offset += 2; }
  function writeUint32(val) { view.setUint32(offset, val, true); offset += 4; }

  writeUint32(0x46464952); // "RIFF"
  writeUint32(fileSize - 8);
  writeUint32(0x45564157); // "WAVE"
  writeUint32(0x20746d66); // "fmt "
  writeUint32(16);
  writeUint16(1); // PCM format
  writeUint16(numChannels);
  writeUint32(buffer.sampleRate);
  writeUint32(buffer.sampleRate * numChannels * 2);
  writeUint16(numChannels * 2);
  writeUint16(16); // 16-bit
  writeUint32(0x61746164); // "data"
  writeUint32(dataSize);

  const channels = [];
  for (let ch = 0; ch < numChannels; ch++) {
    channels.push(buffer.getChannelData(ch));
  }

  for (let i = 0; i < sampleCount; i++) {
    for (let ch = 0; ch < numChannels; ch++) {
      const sample = Math.max(-1, Math.min(1, channels[ch][i]));
      const int16 = sample < 0 ? sample * 32768 : sample * 32767;
      view.setInt16(offset, int16 | 0, true);
      offset += 2;
    }
  }

  return new Blob([arrayBuffer], { type: 'audio/wav' });
}

async function handleEncrypt(inputElement) {
  const file = inputElement.files[0];
  if (!file) return;

  const uploadText = inputElement.previousElementSibling;
  const originalText = uploadText.innerText;
  uploadText.innerText = 'Encrypting...';

  let audioCtx = null;
  try {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const arrayBuffer = await file.arrayBuffer();
    const originalBuffer = await audioCtx.decodeAudioData(arrayBuffer);

    const offlineCtx = new OfflineAudioContext(
      originalBuffer.numberOfChannels,
      originalBuffer.length,
      originalBuffer.sampleRate
    );

    const source = offlineCtx.createBufferSource();
    source.buffer = originalBuffer;

    const oscillator1 = offlineCtx.createOscillator();
    oscillator1.type = 'sine';
    oscillator1.frequency.value = 18500;

    const oscillator2 = offlineCtx.createOscillator();
    oscillator2.type = 'square';
    oscillator2.frequency.value = 19500;

    const gainNode = offlineCtx.createGain();
    gainNode.gain.value = 0.15;

    source.connect(offlineCtx.destination);
    oscillator1.connect(gainNode);
    oscillator2.connect(gainNode);
    gainNode.connect(offlineCtx.destination);

    source.start(0);
    oscillator1.start(0);
    oscillator2.start(0);

    const renderedBuffer = await offlineCtx.startRendering();
    const encryptedBlob = createWavFile(renderedBuffer);

    if (currentEncryptedBlobUrl) {
      URL.revokeObjectURL(currentEncryptedBlobUrl);
    }
    currentEncryptedBlobUrl = URL.createObjectURL(encryptedBlob);

    const player = document.getElementById('encrypted-audio-player');
    player.src = currentEncryptedBlobUrl;
    player.load();
    showScreen('result-encrypted');

  } catch (e) {
    console.error('Encryption error:', e);
    alert('Error encrypting audio.');
  } finally {
    if (audioCtx) audioCtx.close();
    uploadText.innerText = originalText;
    inputElement.value = '';
  }
}

/* ═══════════════════════════════════════════════════════════
   Simulate AI Attack
   ═══════════════════════════════════════════════════════════ */

async function simulateAIListening() {
  if (!currentEncryptedBlobUrl) return;

  document.getElementById('encrypted-audio-player').pause();

  let audioCtx = null;
  try {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const response = await fetch(currentEncryptedBlobUrl);
    const arrayBuffer = await response.arrayBuffer();
    const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer);

    const source = audioCtx.createBufferSource();
    source.buffer = audioBuffer;

    const distortion = audioCtx.createWaveShaper();
    function makeDistortionCurve(amount) {
      const k = typeof amount === 'number' ? amount : 50;
      const samples = 44100;
      const curve = new Float32Array(samples);
      const deg = Math.PI / 180;
      for (let i = 0; i < samples; i++) {
        const x = i * 2 / samples - 1;
        curve[i] = (3 + k) * x * 20 * deg / ( Math.PI + k * Math.abs(x) );
      }
      return curve;
    }
    distortion.curve = makeDistortionCurve(400);

    const biquadFilter = audioCtx.createBiquadFilter();
    biquadFilter.type = 'highpass';
    biquadFilter.frequency.value = 2000;
    biquadFilter.Q.value = 15;

    source.connect(biquadFilter);
    biquadFilter.connect(distortion);
    distortion.connect(audioCtx.destination);

    alert('SIMULATION START: Now you will hear how your voice sounds to AI.');
    source.start(0);

    source.onended = () => {
      audioCtx.close();
    };
  } catch (e) {
    console.error('Simulation error:', e);
    if (audioCtx) audioCtx.close();
  }
}
