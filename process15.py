# Now python3
# 2014
#
from __future__ import with_statement
import os
import sys
import subprocess
import time
import datetime
import smtplib
from email.mime.text import MIMEText
import getopt
import threading
import configparser
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import re
import cgi
from urllib.request import urlopen
import telnetlib
import shlex
import signal
try:
    import pygmail
except:
    pass

STATUS_INITED     =     0
STATUS_READY      =     1 #after config
STATUS_RUNNING    =     2 #all is well
STATUS_ENDED      =     4 #normal end
STATUS_KILLED     =     8 #got a signal
STATUS_LIMITED    =    16 #hit a limit
STATUS_TERMINATED =    32 #stopped on purpose
STATUS_EXIT       =    64 #exit the thread
STATUS_ENDED_RES  =   128 #exit with a non-0 result
STATUS_INVALID    = 32768 #problems with the config, cannot start

stts = {
    STATUS_INITED     : "inited",
    STATUS_READY      : "ready",
    STATUS_RUNNING    : "running",
    STATUS_ENDED      : "ended",
    STATUS_KILLED     : "killed",
    STATUS_LIMITED    : "limited",
    STATUS_TERMINATED : "terminated",
    STATUS_EXIT       : "exit",
    STATUS_ENDED_RES  : "exitres",
    STATUS_INVALID    : "invalid"
    }

#http://www.pixelbeat.org/docs/terminal_colours/
#http://www.cs.rice.edu/~scrosby/software/tf256color/src/256colors.def
CSI="\x1B["
RST=CSI+"m"
colours = {
    "GRY0"  : CSI+"1;30m",

    "RED"  : CSI+"1;31m",
    "RED0" : CSI+"38;5;124m",

    "ORG"  : CSI+"38;5;130m",

    "GRN"  : CSI+"1;32m",
    "GRN0" : CSI+"38;5;118m",

    "YLW"  : CSI+"1;33m",

    "BLU"  : CSI+"1;34m",
    "BLU0" : CSI+"38;5;62m",
    "BLU1" : CSI+"38;5;68m",
    "BLU2" : CSI+"38;5;74m",
    "BLU3" : CSI+"38;5;80m",
    "BLU4" : CSI+"38;5;86m",

    "PRP" : CSI+"1;35m",

    "LBLU" : CSI+"1;36m",
    "GRY1" : CSI+"1;37m"
}

#for v in range(60,99,1):
#    print CSI+"38;5;"+repr(v)+"m",v,RST
#for name, col in colours.items():
#    print col+name+" is this colour"
#    print RST
#sys.exit(0)


# -- Webserver stuff


class MyHandler(BaseHTTPRequestHandler):

    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()

    def do_GET(s):
        #s.send_response(200)
        #s.send_header("Content-type", "text/html")
        #s.end_headers()

        """Get the path and find the parameters"""
        try:
            path, query_string = s.path.split('?', 1)
        except:
            path = s.path
            query_string = ""
            
        params = dict(cgi.parse_qsl(query_string))

        print( timestamp(), s.client_address[0], ":", s.client_address[1], path, query_string )
        #print params

        # maybe a "/do?cmd=start&name=s1"

        # in browser: http://localhost:9191/list
        # or wget localhost:9191/list
        if path == '/list':
            data = ""
            for p in procs:
                data = data + p.info() + "\n"
                for a in p.actions:
                    data = data + "  " + a.info() + "\n"
            s.wfile.write(data.encode(encoding='utf_8'))

        elif path == '/stop':
            if params.has_key('name'):
                stop( params['name'] )
                data = "ok\n"
                s.wfile.write(data.encode(encoding='utf_8'))

        elif path == '/start':
            if params.has_key('name'):
                start( params['name'] ) #via action. Or do it directly?
                data = "ok\n"
                s.wfile.write(data.encode(encoding='utf_8'))

        elif path == '/show':
            """Validate the parameters"""
            if params.has_key('id'):
                data = 'Parameter id: %s\n' % params['id']
                s.wfile.write(data.encode(encoding='utf_8'))
            else:
                data = "Show what?\n"
                s.wfile.write(data.encode(encoding='utf_8'))

        # wget localhost:9192/quit
        elif path == '/quit':
            ans = "ok\n".encode(encoding='utf_8')
            s.wfile.write( ans )
            running = False
            stop_all()
            w.end()

        else:
            data = 'An error occurred.\n'
            s.wfile.write(data.encode(encoding='utf_8'))

class Watcher(threading.Thread):

    def __init__ (self, hostname, port):
        threading.Thread.__init__(self)
        self.hostname = hostname
        self.port = port
        self.server_class = HTTPServer
        self.httpd = self.server_class((hostname, port), MyHandler)
        print( time.asctime(), "Server Starts - %s:%i" % (hostname, port) )
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                self.httpd.handle_request()
            except:
                pass

    def end(self):
        """
        send QUIT request to http server running on <hostname>:<port>
        """
        self.stop = True
        try:
            conn = http.client.HTTPConnection("%s:%d" % (self.hostname, self.port), timeout=1) #, strict=False)
            conn.request("GET", "/quit")
            conn.getresponse()
        except http.client.BadStatusLine: # our responses are not STRICT anymore
            pass
        except:
            print( "Unexpected error (watcher end):", sys.exc_info()[0] )

# -- End webserver stuff

#on_init = self.prog_start()[at="12:00"]

action_re = re.compile( "(.*)\[(.*)\].*", re.IGNORECASE )
#action_re = re.compile("(.*)", re.IGNORECASE)

class Action:
    def __init__(self, cmd):
        #print cmd
        bits = action_re.match(cmd)
        if bits:
            if bits.lastindex == 2:
                cmd = bits.group(1)
                self.cmd = cmd
                self.at = datetime.datetime.now() #default
                self.active = False # for correct after times
                self.params = bits.group(2).split(',')
                #print self.params
                for param in self.params:
                    if param:
                        (k, v) = param.split('=')
                        #print k, v
                        if k == "after": #this is relative to last stop
                            self.at = datetime.datetime.now() + datetime.timedelta(0, int(v))
                        if k == "at":
                            now = datetime.datetime.now()
                            now_str = now.strftime("%Y-%m-%d")
                            hrs = 24
                            # hack for only minutes?
                            if len(v) <= 2:
                                hrs = 1
                                h_str = now.strftime("%H")
                                v = h_str+':'+v
                            self.at = datetime.datetime.strptime(now_str+" "+v, "%Y-%m-%d %H:%M")
                            if self.at <= now:
                                self.at = self.at + datetime.timedelta(hrs, 0)

        else:
            print( "OLD STYLE action." )
            self.cmd = cmd
            self.at = datetime.datetime.now() #default
            self.active = False # for correct after times
            self.params = []
        #print "ACTION:", self.cmd, self.at

    def activate(self):
        for param in self.params:
            if param:
                (k, v) = param.split('=')
                if k == "after": #this is relative to last stop
                    self.at = datetime.datetime.now() + datetime.timedelta(0, int(v))
                if k == "at":
                    now = datetime.datetime.now()
                    now_str = now.strftime("%Y-%m-%d")
                    hrs = 24
                    # hack for only minutes?
                    if len(v) <= 2:
                        hrs = 1
                        h_str = now.strftime("%H")
                        v = h_str+':'+v
                    self.at = datetime.datetime.strptime(now_str+" "+v, "%Y-%m-%d %H:%M")
                    if self.at <= now:
                        self.at = self.at + datetime.timedelta(hrs, 0)
        self.active = True

    def info(self):
        return self.cmd+" "+timestr(self.at)+" "+repr(self.params)
        
class Program(threading.Thread):
    """A overly complex program class"""

    def __init__(self, name):
        threading.Thread.__init__(self)
        self.param = {}
        self.p = None
        self.starts = 0
        self.start_time = None
        self.stop_time  = None
        self.mark0_time = None
        self.runs = 0
        self.sleep = 0.1
        self.actions = []
        self.on_exit = [ [] for x in range(0,256) ] 
        self.on_sig  = [ [] for x in range(0,256) ]
        self.param['name'] = name
        self.param['stdout_fd'] = None
        self.param['stderr_fd'] = None
        self.param['col'] = "" # PJB TODO uhm, don't colours work anymore?
        self.param['rst'] = "" # PJB TODO uhm, don't colours work anymore?
        self.status = STATUS_INITED

    def run(self):
        """
        Check if we are READY. If not, we check for actions
        to do. If we are RUNNING, check if we exited. Sleep.
        """
        while (self.status != STATUS_EXIT):
            while self.has_action() == True:
                action = self.pop_action()
                #print action.info()
                # replace/add/insert stuff here?
                eval( action.cmd )
                action.active = False
            self.check()
            time.sleep( self.sleep )


    def set_config(self, tuples):
        """
        Set the parameters. Check if cwd is okay. Intialize file
        descriptors. Set status to READY if all is ok.
        """
        for tuple in tuples:
            # here we scan for ${VARS} and replace them
            # by g[VARS]. By the way, $SHELLVARS work already.
            #
            tmp = tuple[1]
            for m in re.finditer(r"(\${.*?})", tmp):
                #print '%02d-%02d: %s' % (m.start(), m.end(), m.group(0))
                # Replace
                var = m.group(0)
                key = var[2:-1]
                if key in g:
                    tmp = tmp.replace(var, g[key])
                else:
                    print( "ERROR, undefined variable used." )
                    print( '%s: %02d-%02d: %s' % (tuple[1], m.start(), m.end(), m.group(0)) )
                    #g[key] = "";
                    sys.exit(1)
            self.set_param( tuple[0], tmp )
        #
        try:
            os.chdir( self.get_param('cwd') )
        except:
            self.msg( "Cannot chdir" )
            self.status = STATUS_INVALID
            return
        #
        stdout_fn = self.get_param('stdout')
        if stdout_fn == "PIPE":
            self.param['stdout_fd'] = subprocess.PIPE
        if stdout_fn != None and stdout_fn != "PIPE":
            try:
                self.param['stdout_fd'] = open( stdout_fn, "w" )
            except:
                self.msg( "Cannot open stdout" )
                #set illegal status?
                #self.status = STATUS_INVALID
                self.param['stdout_fd'] = None
        #
        stderr_fn = self.get_param('stderr')
        if stderr_fn == "PIPE":
            self.param['stderr_fd'] = subprocess.PIPE
        if stderr_fn != None and stderr_fn != "PIPE":
            try:
                self.param['stderr_fd'] = open( stderr_fn, "w" )
            except:
                self.msg( "Cannot open stderr" )
                #set illegal status?
                #self.status = STATUS_INVALID
                self.param['stderr_fd'] = None
        #print self.param
        self.status = STATUS_READY

    def set_param(self, p, v):
        if v == "True":
            v = True
        elif v == "None":
            v = None
        elif p == "on_init":
            # on_init = self.start_prog()[]
            # on_init = self.start_prog()[],self.restart()[after=4],self.msg("hi")[]
            # on_init = self.mail_status('start'),self.start_prog()[]
            # on_init:nop() ??
            # clear the default start, we might not want to
            self.actions = []
            actions = v.split(',')
            self.on_init = actions
            for action in actions:
                self.actions.append( Action(action) )
        elif p == "on_exit":
            #on_exit = 0_1;msg("hi"),start("s3"),self.pause(2)[],self.start_prog()[]/2;self.start_prog()[]
            #              ^^ without self it is a global function.                 ^^ ?
            # on_exit = 0;stop_all()[after=12]
            actions = v.split('/')
            for action in actions:
                pair = action.split(';')
                # check for range, e.g. 1_139
                res = pair[0]
                cnt = res.split('_')
                cmdlist = pair[1]
                cmds = cmdlist.split(',')
                rng = []
                if len(cnt) > 1: # we have a range from_to
                    rng = range(int(cnt[0]),int(cnt[1])+1)
                else:
                    rng = range(int(res),int(res)+1) # just one res
                for res in rng:
                    self.on_exit[res] = [] # clear/initialise
                    for cmd in cmds:
                        print( "EXIT:", res, cmd )
                        self.on_exit[res].append( Action(cmd) )
        elif p == "on_sig":
            # on_sig = 15;self.start_prog()[]
            actions = v.split('/')
            for action in actions:
                pair = action.split(';')
                # check for range, e.g. 1_139
                res = pair[0]
                cnt = res.split('_')
                cmdlist = pair[1]
                cmds = cmdlist.split(',')
                rng = []
                if len(cnt) > 1: # we have a range from_to
                    rng = range(int(cnt[0]),int(cnt[1])+1)
                else:
                    rng = range(int(res),int(res)+1) # just one res
                for res in rng:
                    self.on_sig[res] = [] # clear/initialise
                    for cmd in cmds:
                        print( "SIG:", res, cmd )
                        self.on_sig[res].append( Action(cmd) )
        elif p == "col":
            if v == "":
                self.param[p] = ""
                self.param['rst'] = ""
            else:
                if v in colours:
                    self.param[p] = colours[v] #(col = RED in config)
                                               #self.param[p] = CSI+"38;5;"+v+"m"
                    self.param['rst'] = RST
            return
        try:
            v_int = int(v)
            self.param[p] = v_int
        except:
            self.param[p] = v
        #print "param["+p+"]="+repr(v)

    def get_param(self, p):
        return self.param[p]
    
    def _start(self):
        """
        Start the process, set status to RUNNING.
        """
        try:
            args = shlex.split(self.param['cmd'])
            #print args
            self.p = subprocess.Popen(args,\
                                      shell=False,\
                                      bufsize=-1,\
                                      stdout=self.param['stdout_fd'],\
                                      stderr=self.param['stderr_fd'],\
                                      cwd=self.param['cwd'])

            '''
            self.p = subprocess.Popen(self.param['cmd'],\
                                      shell=True,\
                                      bufsize=-1,\
                                      stdout=self.param['stdout_fd'],\
                                      stderr=self.param['stderr_fd'],\
                                      cwd=self.param['cwd'])
            '''
            self.starts += 1
            self.start_time = datetime.datetime.now()
            self.status = STATUS_RUNNING
        except:
            # Already running, binary not found...
            self.status = STATUS_INVALID
        
    def start_prog(self):
        """
        Start running, according to parameters/status.
        When status is KILLED/RES of ENDED, we check parameters.
        """
        if self.status == STATUS_INVALID:
            self.msg( "INVALID" )
            return 0
        elif self.status == STATUS_READY: #begin situation, start
            self._start() 
        elif self.status == STATUS_TERMINATED: #stopped by hand, start
            self._start() 
        elif self.status == STATUS_ENDED: #normal exit
            #check restart count &c.
            if not 'runs' in self.param:  #runs must be in default ini
                self.param['runs'] = 0;   #check on start up?
            if self.param['runs'] == 0:
                self._start()
            elif self.param['runs'] > 0 and\
                    self.runs < self.param['runs']:
                self._start()
            else:
                self.status = STATUS_LIMITED
                self.msg("runs")
                return 0
        elif self.status == STATUS_KILLED: #received a signal
            #check restart count &c.
            if not 'limit_starts' in self.param:
                self.param['limit_starts'] = 0 #move to init somewhere
            if self.param['limit_starts'] > 0 and\
                    self.starts >= self.param['limit_starts']:
                self.status = STATUS_LIMITED
                self.msg("limit_starts")
                return 0
            else:
                self._start()
        elif self.status == STATUS_ENDED_RES: #exit with a result code > 0
            if not 'limit_starts' in self.param:
                self.param['limit_starts'] = 0 #move to init somewhere
            if self.param['limit_starts'] > 0 and\
                    self.starts >= self.param['limit_starts']:
                self.status = STATUS_LIMITED
                self.msg("limit_starts")
                return 0
            else:
                self._start()
        if self.p == None:
            print( "Binary not found:",self.param['name'] )
            self.status = STATUS_INVALID
            stop_all();
            return 0
        self.msg( "Started." )
        self.status = STATUS_RUNNING
        return self.p

    def signal(self, sig):
        self.msg( "SIGNAL" )
        self.p.send_signal(sig)
    
    def stop(self):
        self.msg( "STOP" )
        if self.status == STATUS_RUNNING:
            if self.p:
                try: #for sig in (15, 9):
                    self.p.terminate()
                    counter = 10; #10 secs to terminate, otherwise -KILL
                    res = self.p.poll()
                    while res == None and counter > 0:
                        time.sleep(1)
                        counter = counter - 1
                        res = self.p.poll()
                    if counter == 0:
                        self.signal(9)
                        res = self.p.wait()
                except:
                    print( "Unexpected error (stop):", sys.exc_info()[0] )
                    #Unexpected error: <type 'exceptions.AttributeError'>
                    self.msg( "Wait? "+repr(self.status) )
                self.msg( "Finished." )
                #self.p.terminate()
                self.status = STATUS_TERMINATED
                self.stop_time = datetime.datetime.now()

    def restart(self):
        self.msg( "RESTART/STOP" )
        if self.status == STATUS_RUNNING:
            if self.p:
                try: #for sig in (15, 9):
                    self.p.terminate()
                    counter = 10; #10 secs to terminate, otherwise -KILL
                    res = self.p.poll()
                    while res == None and counter > 0:
                        time.sleep(1)
                        counter = counter - 1
                        res = self.p.poll()
                    if counter == 0:
                        self.signal(9)
                        res = self.p.wait()
                except:
                    print( "Unexpected error (restart):", sys.exc_info()[0] )
                    #Unexpected error: <type 'exceptions.AttributeError'>
                    self.msg( "Wait? "+repr(self.status) )
                self.msg( "RESTART/START" )
                self.status = STATUS_READY
                self.stop_time = datetime.datetime.now()
                self.runs += 1
                self.stop_time = datetime.datetime.now()
                # original on_init was saved.
                for action in self.on_init:
                    self.actions.append( Action(action) )

    
    def stop_and_exit(self):
        self.msgs( "STOP/WAIT" )
        if self.status == STATUS_RUNNING and self.p:
            try:
                self.p.terminate()
                counter = 10; #10 secs to terminale, otherwise -KILL
                res = self.p.poll()
                while res == None and counter > 0:
                    time.sleep(1)
                    counter = counter - 1
                    res = self.p.poll()
                if counter == 0:
                    self.signal(9)
                    res = self.p.wait()
            except:
                print( "Unexpected error (stop_and_exit):", sys.exc_info()[0] )
                self.msg( "wait? "+repr(self.status) )
        self.msg( "Finished." )
        self.stop_time = datetime.datetime.now()
        self.status= STATUS_EXIT

    def limit(self):
        try:
            self.p.terminate()
        except:
            #print "Unexpected error:", sys.exc_info()[0]
            pass
        self.status = STATUS_LIMITED

    def info(self):
        """
        Print a status line depending on status. 
        """
        if self.status == STATUS_INVALID:
            return
        if self.status < STATUS_RUNNING:
            #never even started
            return self.timestamp()+" "+self.param['name']+" PID:"+"---"\
                +" STATUS:"+self.get_stts()\
                +" STARTS:"+repr(self.starts)+" RUNS:"+repr(self.runs)\
                + " TIME:"+"---"
        if self.status > STATUS_RUNNING:
            if self.stop_time:
                stop_time = datetime.datetime.now() - self.stop_time
                stop_time_secs = int(stop_time.seconds)
            else:
                stop_time_secs = 0
            #we stopped, but don't know why yet. normal end, inc runs?
            #                                                      "---"
            return self.timestamp()+" "+self.param['name']+" PID:"+repr(self.p.pid)\
                +" STATUS:"+self.get_stts()\
                +" STARTS:"+repr(self.starts)+" RUNS:"+repr(self.runs)\
                + " TIME:"+secs_to_str(stop_time_secs)
        if self.start_time:
            run_time = datetime.datetime.now() - self.start_time
            run_time_secs = int(run_time.seconds)
            return self.timestamp()+" "+self.param['name']+" PID:"+repr(self.p.pid)\
                + " STATUS:"+self.get_stts()\
                + " STARTS:"+repr(self.starts)+" RUNS:"+repr(self.runs)\
                + " RUNTIME:"+secs_to_str(run_time_secs)
        return "ERROR IN info()"
    
    def check(self): #check if still running ( -> when terminated)
        """
        Check if running, what happened, and what to do.
        """
        if not self.status == STATUS_RUNNING:
            return
        try:
            res = self.p.poll()
        except:
            self.msg( self.get_param('name')+"no poll?"+repr(self.status) )
            return
        #self.read()
        if res != None:
            #print "catch", res, self.p.pid
            if res == 0:
                self.status = STATUS_ENDED
                self.stop_time = self.start_time
                self.runs += 1
                self.msg( "Ended." )
                self.stop_time = datetime.datetime.now()
                self.actions.extend( self.on_exit[0] )
            if res < 0:
                self.status = STATUS_KILLED
                self.stop_time = self.start_time
                self.msg( "Killed by "+repr(res) )
                self.stop_time = datetime.datetime.now()
                # Do we replace all the actions, or perform the
                # on_sig list first, leaving the rest? Latter is done:
                old_actions = self.actions
                self.clear_actions()
                self.actions.extend( self.on_sig[-res] );
                self.actions.extend( old_actions );
                #self.list_actions()
            if res > 0:
                self.status = STATUS_ENDED_RES
                self.stop_time = self.start_time
                self.msg( "Exit with "+repr(res) )
                self.stop_time = datetime.datetime.now()
                self.actions.extend( self.on_exit[res] );
            ##check min_run_time here?
            run_time = datetime.datetime.now() - self.start_time
            run_time_secs = run_time.seconds
            #print "Check min_run_time verses "+repr(run_time_secs)
            if not 'min_run_time' in self.param:
                self.param['min_run_time'] = 0 #move to init somewhere
            if self.param['min_run_time'] > 0 and\
                    run_time_secs < self.param['min_run_time']:
                self.msg( "LIMIT" )
                self.clear_actions()
                self.limit()
        else: # res == None
            self.status = STATUS_RUNNING
            # check time limit
            #self.msg( "Check time here" );
            run_time = datetime.datetime.now() - self.start_time
            run_time_secs = run_time.seconds
            if not 'max_run_time' in self.param:
                self.param['max_run_time'] = 0 #move to init somewhere
            if self.param['max_run_time'] > 0 and\
                    run_time_secs > self.param['max_run_time']:
                self.msg( "Stopping" )
                self.p.terminate() #p.limit() function which sets status?
                self.stop_time = datetime.datetime.now()
            # end check
        return res

    def get_status(self):
        return self.status

    def get_stts(self):
        return stts[self.status][0:3]

    def get_actions(self):
        return self.actions[:]

    def pop_action(self):
        if self.actions:
            return self.actions.pop(0)
        return None

    def has_action(self):
        """
        Should check time on the whole list, shortest at comes first.
        """
        # Nothing to do.
        if not self.actions:
            return False
        #actions_sorted = sorted(actions, key=lambda action: action.at)
        action = self.pop_action()
        if not action.active:
            action.activate()
        time_at = action.at
        self.actions.insert(0, action)
        if time_at <= datetime.datetime.now():
            return True
        return False
    
    def add_action(self, a):
        self.actions.append( Action(a) )

    def push_action(self, a):
        self.actions.insert( 0, Action(a) )

    def clear_actions(self):
        self.actions = []
        
    def list_actions(self):
        for action in self.actions:
            print( action.info() )

    def timestamp(self):
        ts = datetime.datetime.now()
        ts_txt = ts.strftime("%H:%M:%S")
        return ts_txt

    def read(self):
        print( self.p.communicate()[0] )

    def pause(self, s):
        time.sleep(s)

    def msg(self, m, col=0):
        """
        Normal message.
        """
        with print_rlock:
            if self.p:
                print( self.param['col']+self.info(), m, self.param['rst'] )

    def msgs(self, m, col=0):
        """
        Short message.
        """
        with print_rlock:
            if self.p:
                print( self.param['col']+self.timestamp()+" "+self.param['name']+" PID:"+repr(self.p.pid), m, self.param['rst'] )

    def nop(self):
        pass

    def mail_status(self, txt):
        """
        Use mail_me(body) to mail a status line. Appended to txt.
        """
        body = txt + "\n\n" + self.info()
        mail_me(body)
    
# ---------------------------------------------------------------------------

def secs_to_str(t):
  #lunar months?
  div = [ 604800, 86400, 3600, 60, 60 ]
  ind = [ "w", "d", "h", "m", "s" ]

  if t == 0:
      return "00s"

  res_str = ""
  rest = 0
  for i in range( 0, 4 ):
      rest = int(t // div[i])
      if rest > 0:
          #use >= 0 if you want "00h" etc included.
          t -= rest * div[i]
          res_str += ("%02d" % rest) +ind[i]
  if t > 0:
      res_str += ("%02d" % t) +ind[4]
  return res_str;

def hallo():
    with print_rlock:
        print( "hallo" )

def nop():
    pass

def msg(m):
    print( m )
    
def start(n):
    for p in procs:
        name = p.get_param('name')
        if name == n:
            # Push it, in case it is waiting?
            p.add_action("self.start_prog()[]")

def stop(n):
    for p in procs:
        name = p.get_param('name')
        if name == n:
            #p.clear_actions() #or insert at 0?
            p.push_action("self.stop()[]")

def stop_all():
    for p in procs:
        name = p.get_param('name')
        p.clear_actions()
        p.add_action("self.stop_and_exit()[]")

def info_all():
    for p in procs:
        print( p.info() )

def mail(to, fr, subj, body):
    #msg = MIMEText("Your script has ended!")
    msg = MIMEText(body)
    me = "script@erebus"
    you = "P.J.Berck_UvT.nl"
    msg['Subject'] = 'Notice'
    msg['From'] = me
    msg['To'] = you

    s = smtplib.SMTP('smtp.gmail.com',587) 
    s.ehlo()
    s.starttls()
    s.ehlo
    s.login("pberck_gmail.com", "PASSWORD")
    s.sendmail(me, [you], msg.as_string())
    s.close()

def mail_me(body):
    mail("peterberck.se", "pberckgmail.com", "process15.py", body)
    
def timestamp():
    ts = datetime.datetime.now()
    ts_txt = ts.strftime("%H:%M:%S")
    return ts_txt

def timestr(ts):
    ts_txt = ts.strftime("%Y-%m-%d %H:%M:%S")
    return ts_txt

def end():
    sys.exit(0)

def wget_cmd(cmd):
    if w:
        f = urllib2.urlopen('http://'+hostname+':'+repr(port)+'/'+cmd)
        #print f.read(2)
        #os.system('wget http://'+hostname+':'+repr(port)+'/'+cmd)

def wopr_end(url):
    try:
        h, p = url.split(':')
        tn = telnetlib.Telnet( h, p )
        #tn.read_until("login: ")
        tn.write("_CLOSE_\n")
    except:
        print( "Unexpected error (wopr_end):", sys.exc_info()[0] )

# ---------------------------------------------------------------------------

#mail("", "", "", "")

# ---
#
def handler(signum, frame):
    print( 'Signal handler called with signal', signum )
    stop_all()
    
signal.signal(signal.SIGTERM, handler)
#
# ---

config_file = "processes.ini"
g           = {} #global vars for script from cmd line (unused ENV?)

try:
    opts, args = getopt.getopt(sys.argv[1:], "c:p:", ["config="])
except getopt.GetoptError as err:
    print( err ) # will print something like "option -a not recognized"
    sys.exit(2)

for o, a in opts:
    if o in ("-c", "--config"):
        config_file = a
    elif o in ("-p", "--params"):
        # in ini: cmd = sleep ${s1}
        # on cmd: -c ini -p s1:10
        params = a.split(',')
        for param in params:
            k,v = param.split(':')
            g[k] = v
        print( g )
    else:
        assert False, "unhandled option"

procs   = []
config  = configparser.ConfigParser()
read    = config.read( [ config_file ] )
names   = config.items( 'Programs' )
print( names )
dflt    = config.items( "default" )
print( dflt )

print_rlock = threading.RLock()

# Global logfile?
#
G_LOG = False
try:
    g_logfile = config.get( 'global', 'logfile' )
    g_outfile = open( g_logfile, 'a' )
    sys.stderr.write( "ALL OUTPUT WILL BE TO "+str(g_logfile) )
    sys.stdout = g_outfile
    G_LOG = True
except:
    pass

for name, cfg_name in names:
  print( "New program:", name, "=", cfg_name )
  cfg = dflt + config.items( cfg_name )
  p = Program( name )
  p.set_config( cfg )
  if G_LOG:
      p.set_param('col', "")
  procs.append( p ) 

hostname = config.get( 'global', 'hostname' )
port     = config.getint( 'global', 'port' )
#w_col    = config.getint( 'global', 'port' )
try:
    w = Watcher(hostname, port)
except:
    print( "Unexpected error (watcher):", sys.exc_info()[0] )
    print( "Error opening Watcher." )
    sys.exit(1)
w.start()

print( "--------\nStarting\n--------" )

for p in procs:
    p.start()

running = True

while running:
    try:
        running = any( [p.isAlive() for p in procs] )
        time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        print( timestamp(), "ouch!" )
        running = False #set to pass to ignore ctrl-c

#    stop_all()
#    if w:
#        w.end()
#    running = False
running = False
if w:
    w.end()

print( "Joining." )
for p in procs:
    p.join()
#if not any([thread.isAlive() for thread in threads]):
if w:
    w.join()
print( "Joined" )

