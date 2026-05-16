# AuraCast 🛡️🎙️
> **Your voice is your biometrics. Protect it.**

<p align="center">
  <a href="https://www.figma.com/design/dnOt3b30jmYJxvZJQVp1ci/%D0%9E%D0%B1%D1%80%D1%96%D0%B9?node-id=0-1&p=f&t=SrB7E5vYg7XI2haQ-0">
    <img alt="Figma Design" src="https://img.shields.io/badge/Figma-Design-F24E1E?style=for-the-badge&logo=figma&logoColor=white">
  </a>
</p>

AuraCast is a client-side web application designed to protect human voice biometrics from unauthorized AI training and voice cloning, while also providing a robust tool to detect AI-generated audio deepfakes. 

Built entirely with Vanilla JavaScript and the Web Audio API, AuraCast processes all sensitive biometric data locally in the browser—ensuring zero data leakage to external servers.

## ✨ Core Features

### 1. Audio Encryption - Data Poisoning
Prevents AI models from parsing or cloning your voice. 
* **How it works:** When you upload an audio file, AuraCast acts as an adversarial defense tool. It injects high-frequency noise (18.5kHz - 19.5kHz) into the audio spectrum. 
* **The Result:** The modifications are barely noticeable to the human ear, but they act as a "sonic barrier" that completely breaks AI speech-to-text parsers and prevents Voice-to-Voice AI models from extracting clean biometric data.
* **Simulation Mode:** Includes an "AI Attack Simulation" feature that applies distortion and high-pass filters, allowing users to hear exactly what a neural network hears when trying to process the poisoned file.

### 2. AI Voice Detection - Deepfake Scanner
Distinguishes between a living human voice and an AI-generated fake without relying on heavy backend neural networks.
* **How it works:** Utilizes Digital Signal Processing (DSP) heuristics.
* **Analysis Metrics:**
  * **Standard Deviation & Variance:** Human speech is dynamic and chaotic (breathing, micro-pauses). AI generators often produce sound waves that are mathematically "too perfect" and stable.
  * **Zero-Crossing Rate (ZCR):** Analyzes the frequency of signal sign changes to detect unnatural digital artifacts or low-quality vocoders.
  * **Absolute Silence Detection:** Live microphones always record a noise floor (room tone). AI models often generate absolute mathematical silence (`0.0000` amplitude) between words. The scanner flags unnatural silence percentages.

