#!/usr/bin/env python

import signal
from flask import Flask, request, redirect, url_for
from werkzeug.utils import secure_filename
import argparse
import sys
from datetime import timedelta
from flask_cors import CORS
import rospy
from supervisor.srv import *

app = Flask(__name__)
CORS(app)

def signal_handler(signal,frame):
    print "Closing server"
    shutdown_server()
    sys.exit(0)

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

@app.route('/execute/rule-behaviour',methods=['POST'])
def semanticmap_service():
    resp = []
    
    r = request.get_json()
    
    if "rule" not in r.keys():
        resp.append("A 'rule' parameter must be specified")
        resp.append(400)
    else:
        rule_to_execute = r["rule"]
        
        # here it goes all the logic for calling the behaviour
        print "Received rule %s" % rule_to_execute

        rospy.wait_for_service('/execute_behavior')
        try:
            send_rule = rospy.ServiceProxy('/execute_behavior', SendRule)
            send_rule(rule_to_execute)
        except rospy.ServiceException, e:
            print "Service call failed: %s" % e
        
        # you can do this in a single line with a dict {rule:behaviour}
        # a little bit of reflection, which in python is for free
        # if rule == ...
        #   runBehaviour(X)
        # elif rule == ...
        #   runBehaviour(Y)
        # ...

    resp.append("Executing")
    resp.append(200)
    return app.response_class(response=resp[0], status=resp[1])

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='hans-controller-server')
    args = parser.parse_args()
    
    if "linux" in sys.platform.lower():
        signal.signal(signal.SIGINT,signal_handler)
        
    print "Starting server"
    try:
        app.run(debug=True,use_reloader=False,threaded=True,host='0.0.0.0',port=9090)
    except Exception as e:
        print e
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print "Unable to start the service"
