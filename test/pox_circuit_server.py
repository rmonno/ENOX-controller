import sys
import logging
import argparse
import bottle
import json


logging.basicConfig(format='%(asctime)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.DEBUG)
INFO = logging.info


@bottle.get('/hello')
def hello():
    INFO('Enter (http) hello method!')
    return bottle.HTTPResponse(body='Operation completed', status=200)

@bottle.get('/get_topology')
def get_topology():
    INFO('Enter (http) get_topology method!')

    info_ = {"switches": [
             {"00-00-00-00-03-55":[1,"circuit",25165831,"2011-10-01 15:26"]},
             {"00-00-00-00-03-44":[2,"circuit",25165831,"2011-10-01 15:26"]},
             {"00-00-00-00-03-33":[3,"circuit",25165831,"2011-10-01 15:26"]},
            ]}

    return json.dumps(info_, sort_keys=True, indent=4, separators=(',', ': '))

@bottle.get('/get_topology_ports/<dpid>')
def get_ports(dpid):
    INFO('Enter (http) get_topology_ports method: %s!', (dpid,))

    info_ = {"nodes": [
                [15,"POL15",111,1048576,"00-00-11-11-05-1e",3],
                [14,"POL14",111,1048576,"0",0],
                [13,"POL13",111,1048576,"0",0],
                [12,"POL12",111,1048576,"0",0],
                [11,"POL11",111,1048576,"0",0],
                [10,"POL10",111,1048576,"0",0],
                [9,"POL9",111,1048576,"0",0],
                [8,"POL8",111,1048576,"0",0],
                [7,"POL7",111,1048576,"0",0],
                [6,"POL6",111,1048576,"0",0],
                [5,"POL5",111,1048576,"00-00-00-00-00-07",3],
                [4,"POL4",111,1048576,"0",0],
                [3,"POL3",111,1048576,"0",0],
                [2,"POL2",111,1048576,"0",0],
                [1,"POL1",111,1048576,"0",0],
                [0,"POL",111,1048576,"0",0] ]}

    return json.dumps(info_, sort_keys=True, indent=4, separators=(',', ': '))

@bottle.get('/get_flows/<dpid>')
def get_flows(dpid):
    INFO('Enter (http) get_flows method: %s!', (dpid,))
    bottle.abort(500, 'Not implemented yet!')

@bottle.post('/cflow_mod')
def cflow_mod():
    INFO('Enter (http) cflow_mod method!')

    if bottle.request.headers['content-type'] != 'application/json':
        bottle.abort(500, 'Application Type must be json!')

    inport_ = bottle.request.json['inport']
    outport_ = bottle.request.json['outport']
    hard_ = bottle.request.json['hardtime']
    wild_ = bottle.request.json['wildcards']
    command_ = bottle.request.json['command']
    bw_ = bottle.request.json['bandwidth']

    INFO('in=%s, out=%s, hard=%s, wild=%s, comm=%s, bw=%s',
         (inport_, outport_, hard_, wild_, command_, bw_))

    return bottle.HTTPResponse(body='Operation completed', status=201)

@bottle.get('/get_graph')
def get_graph():
    INFO('Enter (http) get_graph method!')

    info_ = {"connexions": [
                {"00-00-00-00-03-55":["circuit",3,"00-00-00-00-03-5E",
                                      13,4294966303,"2011-10-01 15:46"]},
                {"00-00-00-00-03-44":["circuit",3,"00-00-00-00-03-5E",
                                      13,4294966303,"2011-10-01 15:46"]},
                ]
            }

    return json.dumps(info_, sort_keys=True, indent=4, separators=(',', ': '))


def main(argv=None):
    if not argv: argv = sys.argv

    try:
        bug_reporter_ = '<r.monno@nextworks.it>'
        parser_ = argparse.ArgumentParser(description='POX Circuit Test',
                        epilog='Please, report bugs to ' + bug_reporter_,
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        parser_.add_argument('-d', '--debug', default=False,
                        action='store_true', help='set logging level to DEBUG')

        parser_.add_argument('-a', '--address', default='localhost',
                        help='set the pox-circuit server address')

        parser_.add_argument('-p', '--port', default=9999,
                        help='set the pox-circuit server port')

        args_ = parser_.parse_args()

    except Exception as ex:
        print 'Got an Exception parsing flags/options:', ex
        return False

    INFO("%s" % (args_,))
    try:
        bottle.run(host=args_.address, port=args_.port, debug=args_.debug)

    except Exception as ex:
        INFO('Exception: %s', (ex,))
        return False

    INFO('Bye Bye...')
    return True


if __name__ == '__main__':
    sys.exit(main())
