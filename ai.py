import speech_recognition as sr
import spacy
from spacy.lang.en.stop_words import STOP_WORDS
from string import punctuation
from heapq import nlargest
import os
import json
import wave
import time
from vosk import Model, KaldiRecognizer
import pyaudio

# --- Setup for spaCy (Load model once) ---
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("\n[AI ERROR] spaCy model 'en_core_web_sm' not found. Please run 'python -m spacy download en_core_web_sm'")
    nlp = None


# --- 1. Offline Voice-to-Text Conversion (Keeping for structure) ---
MODEL_PATH = "model"
if not os.path.exists(MODEL_PATH):
    print(
        "\n[VOSK ERROR] Model folder 'model' not found. Download the Vosk small English model and place it in the project directory.")
    VOSK_MODEL = None
else:
    VOSK_MODEL = Model(MODEL_PATH)


# --- (Other spaCy setup remains unchanged) ---

# --- 1. Offline Voice-to-Text Conversion (USING VOSK) ---

def voice_to_text():
    """
    Records audio using PyAudio and processes it with the offline Vosk engine.
    """
    if VOSK_MODEL is None:
        return "Voice-to-Text failed: Vosk model not loaded."

    CHANNELS = 1
    RATE = 16000
    CHUNK = 8000

    # We will no longer rely on RECORD_SECONDS

    p = pyaudio.PyAudio()
    stream = p.open(format=pyaudio.paInt16,
                    channels=CHANNELS,
                    rate=RATE,
                    input=True,
                    frames_per_buffer=CHUNK)

    recognizer = KaldiRecognizer(VOSK_MODEL, RATE)

    print("\n--- VOICE INPUT STARTED (VOSK) ---")
    print("STATUS: Recording... Press ENTER when finished speaking.")

    frames = []

    # Use a flag to control the loop, which the user interaction will change
    recording = True

    # --- Start Recording in a separate thread to check for user input simultaneously ---

    # Unfortunately, the PyAudio/Vosk reading is a BLOCKING call and must be done in a loop.
    # The simplest working method in CLI is to run a continuous loop and rely on CTRL+C (which is too harsh)
    # OR: Prompt the user to start, and use a time loop for control, but let's stick to the simplest controllable loop:

    print("STATUS: Speak now, and press Ctrl+C or wait a few seconds of silence to stop.")

    # This loop runs indefinitely until the input buffer is empty or an error occurs.
    # We will rely on PyAudio's stream.read(CHUNK) timeout mechanism for control.

    # NOTE: Since PyAudio's stream.read() is blocking, we can't easily check keyboard input
    # in the same thread. We will revert to a long timeout and a generous loop count.

    # --- Reverting to a TIME-BASED LOOP, but making it user-definable ---

    try:
        max_duration = int(input("Enter max recording time (seconds, e.g., 15): "))
    except ValueError:
        print("Invalid time entered. Defaulting to 15 seconds.")
        max_duration = 15

    loop_count = int(RATE / CHUNK * max_duration)

    print(f"STATUS: Recording for up to {max_duration} seconds...")

    for i in range(0, loop_count):
        try:
            data = stream.read(CHUNK, exception_on_overflow=False)
            frames.append(data)
            recognizer.AcceptWaveform(data)
        except IOError:
            # This exception often occurs when the microphone buffers overflow
            break

    print("STATUS: Finished recording. Processing...")

    # Stop and close the stream
    stream.stop_stream()
    stream.close()
    p.terminate()

    # Final recognition
    recognizer.AcceptWaveform(b'')
    result = json.loads(recognizer.FinalResult())

    recognized_text = result.get('text', '')

    print(f"--- VOICE INPUT ENDED ---")

    if recognized_text:
        return recognized_text.strip()
    else:
        return "Recognition did not capture clear speech."
    # --- 2. Local Text Summarization (FINAL REFINEMENT) ---

def summarize_text(text, min_percentage=0.4):
    """
    Performs extractive text summarization using the spaCy library.
    Ensures a minimum coherence by selecting at least 40% of the sentences
    or a minimum of 2 sentences.
    """
    if nlp is None:
        return "Summarization failed: spaCy model not loaded."

    doc = nlp(text)
    original_sentences = list(doc.sents)

    # Check for short input
    if len(original_sentences) <= 2:
        return f"Summary: (Text is too short for meaningful summary. Original: {text})"

    # CRITICAL CHANGE: Determine the target number of sentences
    # Target = max(2, 40% of original sentences)
    target_num_sentences = max(2, int(len(original_sentences) * min_percentage))

    # 1. Calculate word frequencies
    word_frequencies = {}
    for word in doc:
        if word.text.lower() not in STOP_WORDS and word.text.lower() not in punctuation and word.is_alpha:
            word_frequencies[word.text] = word_frequencies.get(word.text, 0) + 1

    if not word_frequencies:
        return f"Summary: (Could not analyze text. Original: {text})"

    # 2. Normalize frequencies
    max_frequency = max(word_frequencies.values())
    word_frequencies = {word: freq / max_frequency for word, freq in word_frequencies.items()}

    # 3. Score sentences
    sentence_scores = {}
    for sent in original_sentences:
        for word in sent:
            if word.text.lower() in word_frequencies:
                sentence_scores[sent] = sentence_scores.get(sent, 0) + word_frequencies[word.text.lower()]

    # 4. Get the top N sentences based on score
    summary_sentences = nlargest(target_num_sentences, sentence_scores, key=sentence_scores.get)

    # 5. Reorder the selected sentences based on their appearance in the original text
    final_summary_sentences = []

    # Iterate through the original list of sentences to maintain order
    for sent in original_sentences:
        if sent in summary_sentences:
            final_summary_sentences.append(sent.text)

    summary = ' '.join(final_summary_sentences)

    return summary