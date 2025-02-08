import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import magic

def get_file_type(file_path):
    try:
        m = magic.Magic()
        file_description = m.from_file(file_path)
        return file_description
    except Exception as e:
        print(f"Error: {e}")
        return None

def check_type(filetype):
    filters = ['python','php','elf','empty']
    for i in filters:
        if i in filetype.lower():
            return i
    return 0

def send_data(filepath,type):
    with open("/tmp/monitored_file","w") as f:
        f.write(filepath)
        f.close()

def interaction(filepath):
    filetype = get_file_type(filepath)
    check_filetype =  check_type(filetype)
    if check_filetype:
        send_data(filepath,check_filetype)

class MyHandler(FileSystemEventHandler):
    def on_created(self, event):
        if any(part.startswith('.') for part in event.src_path.split('/')):
            return  
        
        else:
            print(f"New file created: {event.src_path}")
            interaction(event.src_path)

observer = Observer()
event_handler = MyHandler()

observer.schedule(event_handler, path="/home/user", recursive=True)

observer.start()

try:
    while True:
        time.sleep(1)  
except KeyboardInterrupt:
    observer.stop()
observer.join()
