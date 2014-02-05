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
                {"swtype":"circuit","swcap":25165831,
                 "id":"00-00-00-00-03-10","noofports":3},
                {"swtype":"circuit","swcap":25165831,
                 "id":"00-00-00-00-03-11","noofports":3},
                {"swtype":"circuit","swcap":25165831,
                 "id":"00-00-00-00-03-12","noofports":2},]}

    return json.dumps(info_, sort_keys=True, indent=4, separators=(',', ': '))

@bottle.get('/get_topology_ports/<dpid>')
def get_ports(dpid):
    INFO('Enter (http) get_topology_ports method: %s!', (dpid,))

    info_ = {}

    if "03-10" in dpid:
        info_ = {"switches": [
                    {"portnum":1,"peerportnum":3,"portbw":72057594037927936,
                     "peerdpid":"00-00-00-00-02-06","portname":"POL1",
                     "portconfig":111,"peercap":1048576},
                    {"portnum":2,"peerportnum":1,"portbw":72057594037927936,
                     "peerdpid":"00-00-00-00-03-11","portname":"POL2",
                     "portconfig":111,"peercap":1048576},
                    {"portnum":3,"peerportnum":1,"portbw":72057594037927936,
                     "peerdpid":"00-00-00-00-03-12","portname":"POL1",
                     "portconfig":111,"peercap":1048576},]}

    elif "03-11" in dpid:
        info_ = {"switches": [
                    {"portnum":1,"peerportnum":2,"portbw":72057594037927936,
                     "peerdpid":"00-00-00-00-03-10","portname":"POL1",
                     "portconfig":111,"peercap":1048576},
                    {"portnum":2,"peerportnum":2,"portbw":72057594037927936,
                     "peerdpid":"00-00-00-00-03-12","portname":"POL2",
                     "portconfig":111,"peercap":1048576},
                    {"portnum":3,"peerportnum":1,"portbw":72057594037927936,
                     "peerdpid":"h3","portname":"POL1",
                     "portconfig":111,"peercap":1048576},]}

    elif "03-12" in dpid:
        info_ = {"switches": [
                    {"portnum":1,"peerportnum":3,"portbw":72057594037927936,
                     "peerdpid":"00-00-00-00-03-10","portname":"POL1",
                     "portconfig":111,"peercap":1048576},
                    {"portnum":2,"peerportnum":2,"portbw":72057594037927936,
                     "peerdpid":"00-00-00-00-03-11","portname":"POL2",
                     "portconfig":111,"peercap":1048576},]}

    return json.dumps(info_, sort_keys=True, indent=4, separators=(',', ': '))

@bottle.get('/get_flows/<dpid>')
def get_flows(dpid):
    INFO('Enter (http) get_flows method: %s!', (dpid,))
    bottle.abort(500, 'Not implemented yet!')

@bottle.put('/cflow_mod')
def cflow_mod():
    INFO('Enter (http) cflow_mod method!')

    if bottle.request.headers['content-type'] != 'application/json':
        bottle.abort(500, 'Application Type must be json!')

    flowid_ = bottle.request.json['flow_id']
    dpid_ = bottle.request.json['dpid']
    inport_ = bottle.request.json['flow']['inport']
    outport_ = bottle.request.json['flow']['outport']
    hard_ = bottle.request.json['flow']['hardtime']
    wild_ = bottle.request.json['flow']['wildcards']
    command_ = bottle.request.json['flow']['command']
    bw_ = bottle.request.json['flow']['bandwidth']

    INFO('fid=%s, dpid=%s, in=%s, out=%s, hard=%s, wild=%s, comm=%s, bw=%s' %
         (flowid_, dpid_, inport_, outport_, hard_, wild_, command_, bw_,))

    return "success:True"

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
