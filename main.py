#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Use PyShark to read pcap files or traffic and analyze them
"""
import csv
from multiprocessing import Process, Manager, JoinableQueue, Queue, cpu_count
from optparse import OptionParser
import os
import pyshark
import socket
import struct
import sys
from time import time
reload(sys)
sys.setdefaultencoding('utf8')

dict_nodes = {}

#GTPV1
# CREATE_PDP_REQUEST   = "16" #"0x10"
# CREATE_PDP_RESPONSE  = "17" #"0x11"
# UPDATE_PDP_REQUEST   = "18" #"0x12"
# UPDATE_PDP_RESPONSE  = "19" #"0x13"
# DELETE_PDP_REQUEST   = "20" #"0x14"
# DELETE_PDP_RESPONSE  = "21" #"0x15"

#GTPV2
# CREATE_SESSION_REQUEST   = "32" #"0x20"
# CREATE_SESSION_RESPONSE  = "33" #"0x21"
# MODIFY_BEARER_REQUEST    = "34" #"0x22"
# MODIFY_BEARER_RESPONSE   = "35" #"0x23"
# DELETE_SESSION_REQUEST   = "36" #"0x24"
# DELETE_SESSION_RESPONSE  = "37" #"0x25"

messages = {'gtp': {1: {16: 'CreatePDPContextRequest', 17: 'CreatePDPContextResponse',
                        18: 'UpdatePDPContextRequest', 19: 'UpdatePDPContextResponse',
                        20: 'DeletePDPContextRequest', 21: 'DeletePDPContextResponse'},
                    2: {32: 'CreateSessionRequest', 33: 'CreateSessionResponse',
                        34: 'ModifyBearerRequest', 35: 'ModifyBearerResponse',
                        36: 'DeleteSessionRequest', 37: 'DeleteSessionResponse'}}}


class Analyzer(Process):

    # def __init__(self, vlan_id, packets_queue, dict_results):
    def __init__(self, vlan_id, packets_queue, results_queue):
        Process.__init__(self)
        self.name = 'Process-{0}'.format(vlan_id)
        self.vlan_id = int(vlan_id)
        self.packets_queue = packets_queue
        self.results_queue = results_queue
        self.dict = {}

    def run(self):

        while True:

            packet = self.packets_queue.get()

            if packet is None:
                # Poison pill means shutdown
                print '%s: Exiting' % self.name
                self.packets_queue.task_done()
                d = {self.vlan_id: self.dict}
                # self.results_queue.put(self.dict)
                self.results_queue.put(d)
                break

            if packet.gtp_message in messages['gtp'][packet.gtp_version].keys():

                # # DEBUG
                # self.dict[1] = '1'
                # self.dict['2'] = 2
                # self.dict[0.25] = None

                # Create a new dictionary for the couple (ip src, ip dst) if it does not exist yet
                ips = (packet.src_ip, packet.dst_ip)
                if ips not in self.dict.keys():
                    self.dict[ips] = {}

                # Create a new counter for the given couple of ips and message type if it does not exist yet
                msg = (packet.gtp_version, packet.gtp_message)
                if msg not in self.dict[ips].keys():
                    self.dict[ips][msg] = 0

                # Count new message
                try:
                    self.dict[ips][msg] += 1
                    print 'Packet #{0} processed'.format(packet.num)
                except KeyError:
                    print 'KeyError, keys: {0},{1}'.format(self.vlan_id, ips, msg)

            # Signal task completed
            self.packets_queue.task_done()

        # DEBUG
        # dict_results = self.dict

        return


class Packet(object):

    def __init__(self, pkt):

        try:
            self.num = int(pkt.number)
            self.vlan_id = int(pkt.layers[1].id)
            self.src_ip = ip2int(pkt.ip.src)
            self.dst_ip = ip2int(pkt.ip.dst)
            gtp = pkt.layers[4]
            try:
                self.gtp_version = int(gtp.version)
            except AttributeError:
                self.gtp_version = 1
            self.gtp_message = int(gtp.message) if self.gtp_version == 1 else int(gtp.message_type)

        except KeyError as e:
            return 'KeyError: {0}'.format(e)

    def __call__(self):
        # return '%s * %s = %s' % (self.gtp_version, self.gtp_message, self.gtp_version * self.gtp_message)
        return '%s, %s, %s, %s' % (self.src_ip, self.dst_ip, self.gtp_version, self.gtp_message)

    # def __str__(self):
    #     # return '%s * %s' % (self.gtp_version, self.gtp_message)
    #     return '%s, %s' % (self.gtp_version, self.gtp_message)

    def num(self):
        return self.num

    def vlan_id(self):
        return self.vlan_id

    def src_ip(self):
        return self.src_ip

    def dst_ip(self):
        return self.dst_ip

    def gtp_version(self):
        return self.gtp_version

    def gtp_message(self):
        return self.gtp_message


def mac_addr(address):
    """
        Convert a MAC address to a readable/printable string
        Args:
            address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
        Returns:
            str: Printable/readable MAC address
    """
    return ':'.join(["%02X" % ord(x) for x in address]).strip()


# def inet_to_str(inet):
#     """Convert inet object to a string
#         Args:
#             inet (inet struct): inet network address
#         Returns:
#             str: Printable/readable IP address
#     """
#     try:
#         return socket.inet_ntoa(inet)
#     except ValueError:
#         sys.exit(2)


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def print_results(results):
    """
    Prints results from dictionaries stored in a JoinableQueue
    :param results: Object of type JoinableQueue
    :return:
    """
    global dict_nodes

    while not results.empty():
        d = results.get()
        for v in d.keys():
            print "VLAN id {0}".format(v)
            for i in d[v].keys():
                src = int2ip(i[0])
                dst = int2ip(i[1])
                if src in dict_nodes.keys():
                    src = dict_nodes[src]
                if dst in dict_nodes.keys():
                    dst = dict_nodes[dst]
                print "\t{0}-{1}".format(src, dst)
                for m in d[v][i]:
                    print "\t\t{0}: {1}".format(messages['gtp'][m[0]][m[1]], d[v][i][m])


def process_pcap(pcap):
    """Process each pcap packet
       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """

    # Establish communication queues
    tasks = {}
    packets_to_process = {}
    results = JoinableQueue()

    for pkt in pcap:

        try:

            # Obtain VLAN id
            vlan_id = pkt.layers[1].id

            # Create queues for the corresponding VLAN if they do not exist
            if vlan_id not in packets_to_process.keys():
                packets_to_process[vlan_id] = JoinableQueue()

            # Create and start tasks for the corresponding VLAN if they do not exist
            if vlan_id not in tasks.keys():
                print 'Creating Analyzer for VLAN id {0}'.format(vlan_id)
                # results[vlan_id] = m.dict()
                tasks[vlan_id] = Analyzer(vlan_id, packets_to_process[vlan_id], results)
                tasks[vlan_id].start()

            # # Add package to queue for the corresponding VLAN
            # if gtp.version == '1':
            #     packets_to_process[vlan_id].put(Packet(int(gtp.version), int(gtp.message)))
            # elif gtp.version == '2':
            #     packets_to_process[vlan_id].put(Packet(int(gtp.version), int(gtp.message_type)))

            packets_to_process[vlan_id].put(Packet(pkt))

        except AttributeError as e:
            print 'AttributeError: {0}'.format(e)

        except KeyError as e:
            print 'KeyError: {0}'.format(e)

    # Add a poison pill for each consumer
    for i in tasks.keys():
        packets_to_process[i].put(None)

    # Wait for all of the tasks to finish
    for i in tasks.keys():
        packets_to_process[i].join()

    results.task_done()

    # Print results
    print_results(results)
    # while not results.empty():
    #     print results.get()


def parse_options(argv):
    """
    Parse received arguments
    :param argv: List of received arguments
    :return: List of options after parsing
    """
    parser = OptionParser(usage="usage: %prog filename.json [-i input_dir] [-o output_dir]", version="%prog 0.1")
    parser.add_option("-n", "--nodesfile", dest="nodes", help="Input nodes.csv file", default="nodes.csv")
    parser.add_option("-i", "--inputport", dest="iport", help="Input port/s", default=None)
    parser.add_option("-f", "--inputfile", dest="ifile", help="Input pcap file/s", default=None)

    options, unused_args = parser.parse_args(argv)

    errmsg = ''
    global dict_nodes

    if options.iport is None and options.ifile is None:
        parser.print_help()
        sys.exit(2)

    if options.nodes:
        # Check nodes file exists
        if os.path.isfile(options.nodes):
            with open(options.nodes, 'rb') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=';', quoting=csv.QUOTE_NONE)
                for row in reader:
                    dict_nodes[row['ip-address']] = row['network-element-name']
                    # DEBUG
                    # print(row['ip-address'], row['network-element-name'])
        else:
            errmsg += 'Input file {0} cannot be found\n'.format(options.nodes)

    if errmsg:
        print errmsg
        parser.print_help()
        sys.exit(2)

    return options


def main(argv):
    """
    Main function to open up a pcap file or read input from a port and print out the packets
    :param argv: list of arguments (program name not included)
    :return: None
    """

    # Store current time
    ts = time()

    # Parse arguments
    options = parse_options(argv)

    print('Processing file {0}...'.format(options.ifile))

    # Determine the number of tasks that can be run in parallel
    num_proc = cpu_count()

    if options.ifile:
        cap = pyshark.FileCapture(options.ifile)
        process_pcap(cap)

    print('...Finished')

    # Print time taken to process all packets
    print('It took {0}'.format(time() - ts))


""" Entry point """
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
