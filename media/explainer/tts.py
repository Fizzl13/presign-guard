"""Narration for the explainer video: one WAV per script segment.

    python tts.py --engine kokoro --voice af_heart --out out
    python tts.py --engine silent --out out     # timing-only placeholder (no model needed)

Writes out/audio/<segment id>.wav and out/durations.json ({id: seconds}).
Kokoro (open-weight neural TTS) needs kokoro-v1.0.onnx and voices-v1.0.bin in
the working directory; the workflow downloads them.
"""

import argparse
import json
import os
import re
import wave

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_RATE = 24000

# How the voice should say things the captions write differently. The x402
# community says "four-oh-two"; a TTS engine reads "402" as "four hundred two".
PRONUNCIATION = [
    (r"\bx402\b", "ex four oh two"),
    (r"\b402\b", "four oh two"),
    (r"\bUSDC\b", "U S D C"),
    (r"\bpresign-guard\b", "pre-sign guard"),
]


def spoken(text):
    for pattern, replacement in PRONUNCIATION:
        text = re.sub(pattern, replacement, text)
    return text


def write_wav(path, samples, rate):
    import numpy as np

    pcm = (np.clip(samples, -1.0, 1.0) * 32767).astype("<i2")
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm.tobytes())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=["kokoro", "silent"], default="kokoro")
    parser.add_argument("--voice", default="af_heart")
    parser.add_argument("--speed", type=float, default=1.0)
    parser.add_argument("--out", default=os.path.join(HERE, "out"))
    args = parser.parse_args()

    import numpy as np

    with open(os.path.join(HERE, "script.json")) as f:
        segments = json.load(f)["segments"]
    audio_dir = os.path.join(args.out, "audio")
    os.makedirs(audio_dir, exist_ok=True)

    kokoro = None
    if args.engine == "kokoro":
        from kokoro_onnx import Kokoro

        kokoro = Kokoro("kokoro-v1.0.onnx", "voices-v1.0.bin")

    durations = {}
    for seg in segments:
        if kokoro:
            samples, rate = kokoro.create(spoken(seg["text"]), voice=args.voice, speed=args.speed, lang="en-us")
        else:
            # ~2.6 words per second, the pace of the real voice.
            rate = SAMPLE_RATE
            samples = np.zeros(int(rate * max(1.5, len(seg["text"].split()) / 2.6)), dtype=np.float32)
        path = os.path.join(audio_dir, f"{seg['id']}.wav")
        write_wav(path, np.asarray(samples, dtype=np.float32), rate)
        durations[seg["id"]] = round(len(samples) / rate, 3)
        print(f"{seg['id']}: {durations[seg['id']]} s")

    with open(os.path.join(args.out, "durations.json"), "w") as f:
        json.dump(durations, f, indent=2)
    print(f"total narration: {round(sum(durations.values()), 1)} s")


if __name__ == "__main__":
    main()
