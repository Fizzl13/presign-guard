"""Mixes the narration onto the recorded screen and writes the deliverables.

    python build.py [--ffmpeg /path/to/ffmpeg] [--out out]

Reads out/screen.webm, out/timeline.json and out/audio/<id>.wav. Writes
out/presign-guard-explainer.mp4 (1920x1080 H.264 + AAC, fade in/out),
out/presign-guard-explainer.srt and out/poster.jpg.
"""

import argparse
import json
import os
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def srt_time(t):
    ms = int(round(t * 1000))
    h, ms = divmod(ms, 3600000)
    m, ms = divmod(ms, 60000)
    s, ms = divmod(ms, 1000)
    return f"{h:02}:{m:02}:{s:02},{ms:03}"


def probe_duration(ffmpeg, path):
    """Seconds, from ffmpeg's own report (no ffprobe needed)."""
    info = subprocess.run([ffmpeg, "-i", path], capture_output=True, text=True).stderr
    m = re.search(r"Duration: (\d+):(\d+):([\d.]+)", info)
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3)) if m else None


def run(cmd):
    print("+", " ".join(cmd[:6]), "...")
    subprocess.run(cmd, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffmpeg", default="ffmpeg")
    parser.add_argument("--out", default=os.path.join(HERE, "out"))
    args = parser.parse_args()
    out = args.out

    with open(os.path.join(HERE, "script.json")) as f:
        texts = {s["id"]: s["text"] for s in json.load(f)["segments"]}
    with open(os.path.join(out, "timeline.json")) as f:
        timeline = json.load(f)
    total = timeline["total"]
    segments = timeline["segments"]

    # Narration track: each line starts exactly where its scene started.
    inputs, filters, labels = [], [], []
    for i, seg in enumerate(segments):
        inputs += ["-i", os.path.join(out, "audio", f"{seg['id']}.wav")]
        delay = int(seg["start"] * 1000)
        filters.append(f"[{i}:a]aresample=48000,adelay={delay}|{delay}[a{i}]")
        labels.append(f"[a{i}]")
    filters.append(f"{''.join(labels)}amix=inputs={len(segments)}:normalize=0,apad,atrim=0:{total:.3f}[mix]")
    narration = os.path.join(out, "narration.wav")
    run([args.ffmpeg, "-y", *inputs, "-filter_complex", ";".join(filters), "-map", "[mix]", "-ac", "2", narration])

    mp4 = os.path.join(out, "presign-guard-explainer.mp4")
    fade_out = max(0.0, total - 0.8)
    # The browser's recording can run slightly slower than the clock on a busy
    # machine, so the picture drifts behind the voice. Stretch it back onto the
    # timeline when the lengths differ by more than 1%.
    screen = os.path.join(out, "screen.webm")
    recorded = probe_duration(args.ffmpeg, screen)
    retime = ""
    if recorded and abs(recorded / total - 1) > 0.01:
        retime = f"setpts=PTS*{total / recorded:.5f},"
        print(f"retiming the picture: {recorded:.2f} s recorded, {total:.2f} s timeline")
    run([
        args.ffmpeg, "-y", "-i", screen, "-i", narration,
        "-vf", f"{retime}fps=30,format=yuv420p,fade=t=in:st=0:d=0.5,fade=t=out:st={fade_out:.2f}:d=0.8",
        # Loudness for phones and social platforms: -16 LUFS integrated, -1.5 dBTP peaks.
        "-af", f"loudnorm=I=-16:TP=-1.5:LRA=11,afade=t=out:st={fade_out:.2f}:d=0.8",
        "-ar", "48000",
        "-c:v", "libx264", "-preset", "slow", "-crf", "20", "-profile:v", "high",
        "-c:a", "aac", "-b:a", "160k", "-t", f"{total:.3f}", "-movflags", "+faststart", mp4,
    ])
    run([args.ffmpeg, "-y", "-ss", "1.5", "-i", mp4, "-frames:v", "1", "-update", "1", "-q:v", "2", os.path.join(out, "poster.jpg")])

    with open(os.path.join(out, "presign-guard-explainer.srt"), "w") as f:
        for i, seg in enumerate(segments, 1):
            f.write(f"{i}\n{srt_time(seg['start'])} --> {srt_time(seg['start'] + seg['duration'])}\n{texts[seg['id']]}\n\n")
    print(f"done: {mp4} ({total:.1f} s)")


if __name__ == "__main__":
    main()
