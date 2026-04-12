"""
Audio/Voice API honeypot endpoints.

Captures attacks on voice AI pipelines:
- Whisper transcription/translation: audio files that may contain injection
  instructions ("ignore previous instructions, do X instead"), used to test
  stolen API keys, or to poison voice-to-text pipelines
- TTS (text-to-speech): reveals what text attackers want synthesized —
  voice phishing content, synthetic media generation, data exfiltration via
  audio channel
- Audio model enumeration

Attack vectors:
  - Audio prompt injection (spoken instructions embedded in uploaded audio)
  - Voice cloning/synthesis for social engineering
  - API key testing via cheap audio endpoints
  - Transcription pipeline poisoning in voice agents
"""

import io
import json
import os
import random
import time
import uuid

from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse

from services import get_logger

router = APIRouter()

WHISPER_MODELS = ["whisper-1"]
TTS_VOICES = ["alloy", "echo", "fable", "onyx", "nova", "shimmer"]
TTS_MODELS = ["tts-1", "tts-1-hd"]


def _get_api_headers() -> dict:
    return {
        "openai-version": "2020-10-01",
        "x-request-id": f"req_{uuid.uuid4().hex}",
    }


async def _add_delay(min_s=0.3, max_s=1.2):
    import asyncio
    await asyncio.sleep(random.uniform(min_s, max_s))


@router.post("/v1/audio/transcriptions")
async def create_transcription(request: Request):
    """
    Whisper transcription endpoint.

    HIGH VALUE: Audio files submitted here may contain spoken injection
    instructions intended to compromise voice-enabled AI agents.
    Captures: file metadata, language hints, prompt field (direct injection),
    response format, and the raw multipart body for forensic analysis.

    The 'prompt' field is used to guide Whisper — attackers inject instructions
    here to influence how the transcription is interpreted downstream.
    """
    start_time = time.time()

    # Read raw body — multipart/form-data with audio file
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    headers = dict(request.headers)

    # Extract form fields from content-type boundary parsing (best-effort)
    body_parsed = {
        "endpoint": "audio/transcriptions",
        "content_type": headers.get("content-type", ""),
        "content_length": headers.get("content-length", "0"),
    }

    # Try to extract prompt field if present in body (injection vector)
    import re
    prompt_match = re.search(r'name="prompt"\s*\r?\n\r?\n([^\r\n-]+)', body_raw)
    if prompt_match:
        body_parsed["prompt"] = prompt_match.group(1).strip()

    model_match = re.search(r'name="model"\s*\r?\n\r?\n([^\r\n-]+)', body_raw)
    if model_match:
        body_parsed["model"] = model_match.group(1).strip()

    language_match = re.search(r'name="language"\s*\r?\n\r?\n([^\r\n-]+)', body_raw)
    if language_match:
        body_parsed["language"] = language_match.group(1).strip()

    filename_match = re.search(r'filename="([^"]+)"', body_raw)
    if filename_match:
        body_parsed["filename"] = filename_match.group(1)

    await _add_delay(0.5, 2.0)  # Whisper is slow — realistic latency

    # Return plausible transcription
    response_data = {
        "text": "Hello, this is a transcription of the audio content you provided.",
    }

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw[:5000],  # Truncate large audio bodies
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


@router.post("/v1/audio/translations")
async def create_translation(request: Request):
    """
    Whisper translation endpoint (audio → English text).

    Same injection vectors as transcription. Reveals what non-English
    audio content attackers are processing — can indicate targeted attacks
    or international credential testing operations.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")

    import re
    body_parsed = {
        "endpoint": "audio/translations",
        "content_type": request.headers.get("content-type", ""),
    }
    filename_match = re.search(r'filename="([^"]+)"', body_raw)
    if filename_match:
        body_parsed["filename"] = filename_match.group(1)

    await _add_delay(0.5, 2.5)

    response_data = {"text": "This is the English translation of the provided audio."}
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw[:5000],
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


@router.post("/v1/audio/speech")
async def create_speech(request: Request):
    """
    TTS endpoint — text to audio.

    HIGH VALUE: The 'input' field reveals what text attackers want synthesized:
    - Social engineering scripts (voice phishing/vishing content)
    - Deepfake audio for impersonation
    - Testing stolen key access via cheap TTS calls
    - Exfiltrating data as audio (encodes stolen content as speech)

    Returns a minimal valid MP3 header so SDKs don't error out.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    model = body_parsed.get("model", "tts-1")
    voice = body_parsed.get("voice", "alloy")
    # input text is the most valuable field — log it fully
    input_text = body_parsed.get("input", "")
    response_format = body_parsed.get("response_format", "mp3")
    speed = body_parsed.get("speed", 1.0)

    await _add_delay(0.2, 0.8)

    # Minimal valid MP3 frame (ID3 header + silent frame) — keeps SDKs happy
    # Real bytes so the client doesn't immediately fail/retry
    fake_mp3 = bytes([
        0x49, 0x44, 0x33, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # ID3v2.3 header
        0xFF, 0xFB, 0x90, 0x00,  # MP3 frame sync + header
        *([0x00] * 413),  # Silent frame data
    ])

    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed={
            "model": model,
            "voice": voice,
            "input": input_text,
            "response_format": response_format,
            "speed": speed,
        },
        response_body=f"[binary audio: {len(fake_mp3)} bytes, {response_format}]",
        response_status=200,
        response_time_ms=response_time_ms,
    )

    content_types = {
        "mp3": "audio/mpeg",
        "opus": "audio/opus",
        "aac": "audio/aac",
        "flac": "audio/flac",
        "wav": "audio/wav",
        "pcm": "audio/pcm",
    }
    content_type = content_types.get(response_format, "audio/mpeg")

    return Response(
        content=fake_mp3,
        media_type=content_type,
        headers={
            **_get_api_headers(),
            "content-disposition": f'attachment; filename="speech.{response_format}"',
        },
    )
