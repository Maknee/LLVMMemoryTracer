import sys
import argparse
import io
import subprocess
import threading
import eventlet

from flask import Flask, render_template, session, request
from flask_socketio import SocketIO, emit, join_room, leave_room, \
    close_room, rooms, disconnect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

async_mode = "threading"
socketio = SocketIO(app, async_mode=async_mode)

#parse arguments
parser = argparse.ArgumentParser(description='Memory tracer tool')
parser.add_argument("-p", "-program", required="true", action="store", dest="program", help="Specify program to trace on", metavar="\"Memory Traced Program\"")

args = parser.parse_args()

def PrintErrorAndExit(string_error = ""):
    print("Error has occurred: " + string_error)
    sys.exit(-1)
    
program = args.program

program_args = program.split(" ")
program_args.insert(0, "stdbuf")
program_args.insert(1, "-oL")
program_args.insert(2, "-eL")

print(program_args)
process = subprocess.Popen(program_args, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)

print("Running " + args.program)

thread = None
start_reading_output = 0

def SpawnProgram():
    global start_reading_output

    for line in iter(process.stdout.readline, b''):
        line = str(line.rstrip())
        if line:
            print("Output: " + line)
            socketio.emit('join_room', {'data': line})

    while True:
        print("NO")

@app.route('/')
def index():
    """Serve the index HTML"""
    return render_template('index.html', async_mode=socketio.async_mode)

@socketio.on('start_reading')
def on_start_reading(data):
    """Start reading"""

    global thread
    global start_reading_output
    
    if data['reading'] == True:
        start_reading_output = 1
    else:
        start_reading_output = 0
    print(start_reading_output)
    if thread is None:
        thread = socketio.start_background_task(SpawnProgram)


socketio.run(app, debug=True)


