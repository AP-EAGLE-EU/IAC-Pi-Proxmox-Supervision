#!/usr/bin/python3
from flask import Flask, request, make_response
from gpiozero import TonalBuzzer
import time
import threading

app = Flask(__name__)
BUZZER_PIN = 18
lock       = threading.Lock()
buzzer     = TonalBuzzer(BUZZER_PIN)

# ------------------------------------------------------------------------------------------
def play_song(song):
    with lock:
        try:
            buzzer.stop()
            for note, duration in song:
                if note is not None:
                    buzzer.play(note)
                time.sleep(duration)
                buzzer.stop()
                time.sleep(0.03)
            return make_response("Song played!", 200)
        except Exception as e:
            buzzer.stop()
            return make_response(f"Error: {e}", 500)

# ------------------------------------------------------------------------------------------
@app.route('/bip', methods=['POST'])
def bip():
    with lock:
        try:
            buzzer.stop()
            buzzer.play('A4')
            time.sleep(1)
            buzzer.stop()
            return make_response("Bip OK", 200)
        except Exception as e:
            buzzer.stop()
            return make_response(f"Error: {e}", 500)

# ------------------------------------------------------------------------------------------
@app.route('/alert', methods=['POST'])
def alert():
    with lock:
        try:
            buzzer.stop()
            buzzer.play('C5')
            time.sleep(2)
            buzzer.stop()
            return make_response("Buzzed!", 200)
        except Exception as e:
            buzzer.stop()
            return make_response(f"Error: {e}", 500)

# ------------------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)