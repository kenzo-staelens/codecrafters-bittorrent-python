import sys
import trace
import threading
import time

class HangableThread(threading.Thread):
  def __init__(self, *args, **keywords):
    threading.Thread.__init__(self, *args, **keywords)
    self.killed = False

  def start(self,timeout):
    self.__run_backup = self.run
    self.run = self.__run      
    threading.Thread.start(self)
    def killafter(t,timeout):
        time.sleep(timeout)
        t.kill()
    threading.Thread(target=killafter,args=(self,timeout)).start()

  def __run(self):
    sys.settrace(self.globaltrace)
    self.__run_backup()
    self.run = self.__run_backup

  def globaltrace(self, frame, event, arg):
    if event == 'call':
      return self.localtrace
    else:
      return None

  def localtrace(self, frame, event, arg):
    if self.killed:
      if event == 'line':
        raise SystemExit()
    return self.localtrace

  def kill(self):
    self.killed = True