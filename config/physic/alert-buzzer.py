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
@app.route('/alert', methods=['POST'])
def alert():
    with lock:
        try:
            buzzer.stop()
            buzzer.play(880) # 880 Max - gpiozero
            time.sleep(2)
            buzzer.stop()
            return make_response("Buzzed!", 200)
        except Exception as e:
            buzzer.stop()
            return make_response(f"Error: {e}", 500)

# ------------------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)