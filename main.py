#!/usr/bin/env python
"""
Use PyShark to read pcap files or traffic and analyze them
"""
import datetime
# import multiprocessing as mp
from multiprocessing import Process, Queue, JoinableQueue, cpu_count
# import queue # imported for using queue.Empty exception
from optparse import OptionParser
import pyshark
# from Queue import Queue
import socket
import sys
import time
reload(sys)
sys.setdefaultencoding('utf8')

# from dpkt.compat import compat_ord

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


# class Analyzer(Process):
#
#     def __init__(self, vlan_id, packet_queue, result_queue):
#         Process.__init__(self)
#         self.name = 'Process-{0}'.format(vlan_id)
#         self.packet_queue = packet_queue
#         self.result_queue = result_queue
#
#     def run(self):
#         proc_name = self.name
#         while True:
#             try:
#                 # next_packet = self.packet_queue.get()
#                 next_packet = self.packet_queue.get_nowait()
#                 if next_packet is None:
#                     # Poison pill means shutdown
#                     print '%s: Exiting' % proc_name
#                     self.packet_queue.task_done()
#                     break
#                 print '%s: %s' % (proc_name, next_packet)
#                 answer = next_packet()
#                 self.packet_queue.task_done()
#                 self.result_queue.put(answer)
#             except AttributeError as e:
#                 print 'AttributeError: {0}'.format(e)
#         return
#
#
# class Packet(object):
#
#     """Process a packet from a pcap file
#        Args:
#            id: VLAN ID (-1 if none)
#            data: packet data
#     """
#
#     def __init__(self, gtp_version, gtp_message):
#         """Class constructor
#            Args:
#                gtp_message: GTP message
#         """
#         self.gtp_version = gtp_version
#         self.gtp_message = gtp_message
#
#     def __call__(self):
#         return "{0} - {1}".format(self.gtp_version, self.gtp_message)
#
#     def __str__(self):
#         return "{0} - {1}".format(self.gtp_version, self.gtp_message)


class Analyzer(Process):
    def __init__(self, vlan_id, task_queue, result_queue):
        Process.__init__(self)
        self.name = 'Process-{0}'.format(vlan_id)
        self.task_queue = task_queue
        self.result_queue = result_queue
        self.counters = {}

    def run(self):
        proc_name = self.name
        while True:
            packet = self.task_queue.get()
            if packet is None:
                # Poison pill means shutdown
                print '%s: Exiting' % proc_name
                self.task_queue.task_done()
                break
            if packet.gtp_message not in self.counters.keys():
                self.counters[packet.gtp_message] = 0
            self.counters[packet.gtp_message] += 1                
            # print '%s: %s' % (proc_name, packet)
            try:
                print 'GTP message {0} count {1}'.format(messages['gtp'][packet.gtp_version][packet.gtp_message],
                                                         self.counters[packet.gtp_message])
            except KeyError:
                print 'Unknown GTP message code {0}'.format(packet.gtp_message)
            answer = packet()
            self.task_queue.task_done()
            self.result_queue.put(answer)
        return


class Packet(object):

    # def __init__(self, a, b):
    #     self.a = a
    #     self.b = b

    def __init__(self, gtp_version, gtp_message):
        self.gtp_version = gtp_version
        self.gtp_message = gtp_message

    def __call__(self):
        # time.sleep(0.1)  # pretend to take some time to do the work
        # return '%s * %s = %s' % (self.a, self.b, self.a * self.b)
        return '%s * %s = %s' % (self.gtp_version, self.gtp_message, self.gtp_version * self.gtp_message)

    def __str__(self):
        # return '%s * %s' % (self.a, self.b)
        return '%s * %s' % (self.gtp_version, self.gtp_message)
    
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


def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    # Commented out as inet_ntop only exists in unix version of socket
    # try:
    #     return socket.inet_ntop(socket.AF_INET, inet)
    # except ValueError:
    #     return socket.inet_ntop(socket.AF_INET6, inet)

    try:
        return socket.inet_ntoa(inet)
    except ValueError:
        sys.exit(2)


def process_pcap(pcap):
    """Process each pcap packet
       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # Establish communication queues
    processes = {}
    packets_to_process = {}
    results = {}

    for pkt in pcap:

        try:

            # Obtain VLAN id
            vlan_id = pkt.layers[1].id

            # Obtain GTP version and message
            gtp = pkt.layers[4]

            # Create queues for the corresponding VLAN if they do not exist
            if vlan_id not in packets_to_process.keys():
                packets_to_process[vlan_id] = JoinableQueue()
                results[vlan_id] = Queue()

            # Create and start processes for the corresponding VLAN if they do not exist
            if vlan_id not in processes.keys():
                # processes[vlan_id] = Analyzer(vlan_id, packets_to_process[vlan_id], results[vlan_id])
                print 'Creating Analyzer for VLAN id {0}'.format(vlan_id)
                processes[vlan_id] = Analyzer(vlan_id, packets_to_process[vlan_id], results[vlan_id])
                processes[vlan_id].start()

            # Add package to queue for the corresponding VLAN
            if gtp.version == '1':
                # packets_to_process[vlan_id].put(Packet(gtp.version, gtp.message))
                packets_to_process[vlan_id].put(Packet(int(gtp.version), int(gtp.message)))
            elif gtp.version == '2':
                # packets_to_process[vlan_id].put(Packet(gtp.version, gtp.message_type))
                packets_to_process[vlan_id].put(Packet(int(gtp.version), int(gtp.message_type)))

        except AttributeError as e:
            print 'AttributeError: {0}'.format(e)

        except KeyError as e:
            print 'KeyError: {0}'.format(e)

    # Add a poison pill for each consumer
    for i in processes.keys:
        packets_to_process[i].put(None)

    # Wait for all of the tasks to finish
    for i in processes.keys:
        packets_to_process[i].join()


def parse_options(argv):
    """
    Parse received arguments
    :param argv: List of received arguments
    :return: List of options after parsing
    """
    parser = OptionParser(usage="usage: %prog filename.json [-i input_dir] [-o output_dir]", version="%prog 0.1")
    parser.add_option("-i", "--inputport", dest="iport", help="Input port/s", default=None)
    parser.add_option("-f", "--inputfile", dest="ifile", help="Input pcap file/s", default=None)

    options, unused_args = parser.parse_args(argv)

    errmsg = ''

    if options.iport is None and options.ifile is None:
        parser.print_help()
        sys.exit(2)

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
    # Parse arguments
    options = parse_options(argv)

    # Determine the number of processes that can be run in parallel
    num_proc = cpu_count()

    if options.ifile:
        cap = pyshark.FileCapture(options.ifile)
        process_pcap(cap)


""" Entry point """
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
