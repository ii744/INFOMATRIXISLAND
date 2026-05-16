function showScreen(screenId) {
    const screens = ['main-screen', 'encrypt-screen', 'detect-screen', 'result-human', 'result-ai', 'result-encrypted'];
    screens.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.style.display = (id === screenId) ? 'block' : 'none';
        }
    });
}



function triggerFileChoose() {

    document.getElementById('file-chooser').click();
}

let currentEncryptedBlob = null;

// ==========================================
// 1: AI Detect
// ==========================================
async function handleDetect(inputElement) {
    const file = inputElement.files[0];
    if (!file) return;

    const uploadText = inputElement.previousElementSibling;
    const originalText = uploadText.innerText;
    uploadText.innerText = "Scanning...";

    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const arrayBuffer = await file.arrayBuffer();
        const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer);
        const data = audioBuffer.getChannelData(0);

        const sampleRate = audioBuffer.sampleRate;
        
        let maxAmplitude = 0;
        for (let i = 0; i < data.length; i++) {
            let absVal = Math.abs(data[i]);
            if (absVal > maxAmplitude) maxAmplitude = absVal;
        }
        const silenceThreshold = maxAmplitude * 0.008; 

        // 2. Аналіз блоками по 0.4 секунди
        const windowSize = Math.floor(sampleRate * 0.4); 
        
        let totalSpeechBlocks = 0;
        let aiSuspiciousBlocks = 0;
        let isPoisoned = false;

        console.log(`--- SCANNING INTEGRITY FOR: ${file.name} ---`);

        for (let i = 0; i < data.length; i += windowSize) {
            let end = Math.min(i + windowSize, data.length);
            let chunkData = data.subarray(i, end);

            if (chunkData.length < windowSize * 0.5) continue;

            let chunkCrossings = 0;
            let sumSquares = 0;
            let exactSilenceSamples = 0;

            for (let j = 0; j < chunkData.length - 1; j++) {
                sumSquares += chunkData[j] * chunkData[j];
                if ((chunkData[j] > 0 && chunkData[j + 1] <= 0) || (chunkData[j] < 0 && chunkData[j + 1] >= 0)) {
                    chunkCrossings++;
                }
                if (Math.abs(chunkData[j]) < silenceThreshold) {
                    exactSilenceSamples++;
                }
            }

            let rms = Math.sqrt(sumSquares / chunkData.length);
            let zcrRate = chunkCrossings * (sampleRate / chunkData.length); 
            let silencePercent = (exactSilenceSamples / chunkData.length) * 100;

          
            if (rms > silenceThreshold) {
                totalSpeechBlocks++;

                if (zcrRate > 3800) {
                    isPoisoned = true;
                    console.log(`[ALERT] Data Poisoning detected at ${(i/sampleRate).toFixed(1)}s`);
                    break; 
                }

                if (zcrRate < 320 || silencePercent > 40.0) {
                    aiSuspiciousBlocks++;
                    console.log(`[WARNING] Suspicious patterns at ${(i/sampleRate).toFixed(1)}s (ZCR: ${zcrRate.toFixed(0)}, Silence: ${silencePercent.toFixed(1)}%)`);
                }
            }
        }

     
        let isAi = false;

        if (isPoisoned) {
            isAi = true;
        } 
        else if (totalSpeechBlocks > 0 && (aiSuspiciousBlocks / totalSpeechBlocks) > 0.25) {
            isAi = true;
            console.log(`Verdict: AI Generated (${((aiSuspiciousBlocks / totalSpeechBlocks) * 100).toFixed(1)}% suspicious elements)`);
        } else {
            console.log("Verdict: Authentic Human Voice");
        }

       
        if (isAi) {
            showScreen('result-ai');
        } else {
            showScreen('result-human');
        }

    } catch (e) {
        console.error(e);
        alert("Помилка читання аудіо.");
    } finally {
        uploadText.innerText = originalText;
        inputElement.value = ""; 
    }
}
/// ==========================================
// 2: Data Poisoning 
// ==========================================


function createWavFile(buffer) {
    const numOfChan = buffer.numberOfChannels;
    const length = buffer.length * numOfChan * 2 + 44;
    const bufferArray = new ArrayBuffer(length);
    const view = new DataView(bufferArray);
    let offset = 0;
    let pos = 0;

    function setUint16(data) { view.setUint16(offset, data, true); offset += 2; }
    function setUint32(data) { view.setUint32(offset, data, true); offset += 4; }

    setUint32(0x46464952); // "RIFF"
    setUint32(length - 8); // file length - 8
    setUint32(0x45564157); // "WAVE"
    setUint32(0x20746d66); // "fmt " chunk
    setUint32(16); // length = 16
    setUint16(1); // PCM (uncompressed)
    setUint16(numOfChan);
    setUint32(buffer.sampleRate);
    setUint32(buffer.sampleRate * 2 * numOfChan); // avg. bytes/sec
    setUint16(numOfChan * 2); // block-align
    setUint16(16); // 16-bit
    setUint32(0x61746164); // "data" - chunk
    setUint32(length - pos - 4); // chunk length

    const channels = [];
    for (let i = 0; i < buffer.numberOfChannels; i++) {
        channels.push(buffer.getChannelData(i));
    }

    while (pos < buffer.length) {
        for (let i = 0; i < numOfChan; i++) {
            let sample = Math.max(-1, Math.min(1, channels[i][pos]));
            sample = (0.5 + sample < 0 ? sample * 32768 : sample * 32767) | 0;
            view.setInt16(offset, sample, true);
            offset += 2;
        }
        pos++;
    }
    return new Blob([bufferArray], { type: "audio/wav" });
}

async function handleEncrypt(inputElement) {
    const file = inputElement.files[0];
    if (!file) return;

    const uploadText = inputElement.previousElementSibling;
    const originalText = uploadText.innerText;
    uploadText.innerText = "Encrypting...";

    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
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
        
        currentEncryptedBlob = createWavFile(renderedBuffer);
        

        const audioUrl = URL.createObjectURL(currentEncryptedBlob);
        const player = document.getElementById('encrypted-audio-player');
        player.src = audioUrl;
        player.load(); 
        showScreen('result-encrypted');

    } catch (e) {
        console.error(e);
        alert("Помилка шифрування.");
    } finally {
        uploadText.innerText = originalText;
        inputElement.value = ""; 
    }
}

// ==========================================
// 3: Simulate AI Attack
// ==========================================

async function simulateAIListening() {
    if (!currentEncryptedBlob) return;

    document.getElementById('encrypted-audio-player').pause();

    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const arrayBuffer = await currentEncryptedBlob.arrayBuffer();
    const audioBuffer = await audioCtx.decodeAudioData(arrayBuffer);

    const source = audioCtx.createBufferSource();
    source.buffer = audioBuffer;


    const distortion = audioCtx.createWaveShaper();
    function makeDistortionCurve(amount) {
        let k = typeof amount === 'number' ? amount : 50,
            n_samples = 44100,
            curve = new Float32Array(n_samples),
            deg = Math.PI / 180, i = 0, x;
        for ( ; i < n_samples; ++i ) {
            x = i * 2 / n_samples - 1;
            curve[i] = ( 3 + k ) * x * 20 * deg / ( Math.PI + k * Math.abs(x) );
        }
        return curve;
    }
    distortion.curve = makeDistortionCurve(400);

    const biquadFilter = audioCtx.createBiquadFilter();
    biquadFilter.type = "highpass";
    biquadFilter.frequency.value = 2000;
    biquadFilter.Q.value = 15;

    source.connect(biquadFilter);
    biquadFilter.connect(distortion);
    distortion.connect(audioCtx.destination);

    alert("SIMULATION START: Now you you will hear how your voice sounds to AI.");
    source.start(0);
}


