# -*- coding: utf-8 -*-
# !/usr/bin/env python
"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import csv
import datetime
import dpkt
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from multiprocessing import Process, JoinableQueue, cpu_count
import numpy as np
from optparse import OptionParser
import os
import socket
import struct
import sys
from time import time

# Ports
PORT_GTP_U = 2152
PORT_GTP_C = 2123
PORT_DIAMETER = 3868
PORT_S1AP = 36412

# Messages
messages = {'gtp': {1: {1: 'EchoRequest', 2: 'EchoResponse',
                        16: 'CreatePDPContextRequest', 17: 'CreatePDPContextResponse',
                        18: 'UpdatePDPContextRequest', 19: 'UpdatePDPContextResponse',
                        20: 'DeletePDPContextRequest', 21: 'DeletePDPContextResponse'},
                    2: {32: 'CreateSessionRequest', 33: 'CreateSessionResponse',
                        34: 'ModifyBearerRequest', 35: 'ModifyBearerResponse',
                        36: 'DeleteSessionRequest', 37: 'DeleteSessionResponse',
                        170: 'ReleaseAccessBearersRequest', 171: 'ReleaseAccessBearersResponse'}},
            'diameter': {1: 'Credit-Control Request', 0: 'Credit-Control Answer'}}

# Create the list of GTP messages
labels_gtp = []
for v in messages['gtp'].keys():
    for i, m in enumerate(messages['gtp'][v]):
        if i % 2:
            labels_gtp.append(messages['gtp'][v][m][:-8])

dict_nodes = {}


# class Analyzer(Process):
#
#     def __init__(self, task_queue, result_queue):
#         Process.__init__(self)
#         self.task_queue = task_queue
#         self.result_queue = result_queue
#
#     def run(self):
#         proc_name = self.name
#         while True:
#             next_task = self.task_queue.get()
#             if next_task is None:
#                 # Poison pill means shutdown
#                 print('{}: Exiting'.format(proc_name))
#                 self.task_queue.task_done()
#                 break
#             print('{}: {}'.format(proc_name, next_task))
#             answer = next_task()
#             self.task_queue.task_done()
#             self.result_queue.put(answer)
#         return


class Analyzer(Process):
    """
    Class to implement process for packets from a given VLAN id
    """

    def __init__(self, vlan_id, protocol, packets_queue, results_queue):
        """
        Class constructor
        :param vlan_id:  VLAN id
        :param protocol: Protocol (GTP, GTPv2, Diameter...)
        :param packets_queue: Queue of packets to process
        :param results_queue: Queue of results
        """
        Process.__init__(self)
        self.name = 'Process-{}'.format(vlan_id)
        self.vlan_id = vlan_id
        self.protocol = protocol
        self.packets_queue = packets_queue
        self.results_queue = results_queue
        self.sum_values = {}
        self.dict = {}

    def run(self):

        while True:

            packet = self.packets_queue.get()

            if packet is None:
                # Poison pill means shutdown
                print('{}: Exiting'.format(self.name))
                self.packets_queue.task_done()
                d = {self.vlan_id: self.dict}
                # self.print_barchar()
                self.results_queue.put(d)
                break

            if packet.message_code in messages['gtp'][packet.gtp_v].keys():

                # Create a new dictionary for the couple (ip src, ip dst) if it does not exist yet
                ips = (packet.src_ip, packet.dst_ip)
                if ips not in self.dict.keys():
                    self.dict[ips] = {}

                # Create a new counter for the given couple of ips and message type if it does not exist yet
                msg = (packet.gtp_v, packet.message_code)
                if msg not in self.dict[ips].keys():
                    self.dict[ips][msg] = 0

                # Count new message
                try:
                    self.dict[ips][msg] += 1
                    print('Packet #{} processed'.format(packet.num))
                except KeyError:
                    print('KeyError, keys: {},{}'.format(self.vlan_id, ips, msg))

            # Signal task completed
            self.packets_queue.task_done()

        # DEBUG
        # dict_results = self.dict

        return


class Packet(object):
    """
    Class to process packets from a pcap file
    """

    def __init__(self, pkt, ts, num):
        """
        Class constructor
        :param pkt: packet as read from pcap file
        :param ts: packet timestamp
        """
        try:
            self.num = num
            print('Packet number: {}'.format(self.num))

            self.ts = str(datetime.datetime.utcfromtimestamp(ts))
            print('Timestamp: {}'.format(self.ts))

            # Unpack the Ethernet frame (mac src/dst, ethertype)
            eth = dpkt.ethernet.Ethernet(pkt)
            print('Ethernet Frame: ', Packet.mac_addr(eth.src), Packet.mac_addr(eth.dst), eth.type)

            # Extract the VLAN id if any, set it to -1 elsewhere
            self.vlan_id = eth.vlanid if eth.type == dpkt.ethernet.ETH_TYPE_8021Q else -1

            # Now unpack the data within the Ethernet frame (the IP packet)
            # Pulling out src, dst, length, fragment info, TTL, and Protocol
            ip = eth.data

            # Obtain IP source and destionation addresses
            self.src_ip = ip.src
            self.dst_ip = ip.dst

            # UDP
            if isinstance(ip.data, dpkt.udp.UDP):

                udp = ip.data

                # GTP-C
                if udp.sport == PORT_GTP_C or udp.dport == PORT_GTP_C:
                    upd_data_list = ["%02X" % x for x in udp.data]
                    self.gtp_v = Packet.get_gtp_version(int(upd_data_list[0], 16))
                    self.protocol = 'GTP' if self.gtp_v == 1 else 'GTPv2'
                    self.message_code = int(upd_data_list[1], 16)
                    self.message_text = messages['gtp'][self.gtp_v][int(upd_data_list[1], 16)]
                    print('This is GTP-C {}'.format(self.protocol))

                # GTP-U
                elif udp.sport == PORT_GTP_U or udp.dport == PORT_GTP_U:
                    upd_data_list = ["%02X" % x for x in udp.data]
                    self.gtp_v = Packet.get_gtp_version(int(upd_data_list[0], 16))
                    self.protocol = 'GTP' if self.gtp_v == 1 else 'GTPv2'
                    self.message_code = int(upd_data_list[1], 16)
                    self.message_text = messages['gtp'][self.gtp_v][self.message_code]
                    print('This is GTP-U version {}'.format(self.gtp_v))

            # TCP
            elif isinstance(ip.data, dpkt.tcp.TCP):

                tcp = ip.data

                # Diameter
                if tcp.sport == PORT_DIAMETER or tcp.dport == PORT_DIAMETER:
                    tcp_data_list = ["%02X" % x for x in tcp.data]
                    self.protocol = 'DIAMETER'
                    self.message_code = Packet.get_diam_message_code(int(tcp_data_list[0], 16))
                    self.message_text = messages['diameter'][self.message_code]
                    print('This is Diameter message {}'.format(self.message_text))

            # SCTP
            elif isinstance(ip.data, dpkt.sctp.SCTP):
            # elif ip.p == 132:        # This is SCTP

                sctp = ip.data

                # sctp_data_list = ["%02X" % x for x in sctp.data]

                # S1AP
                if sctp.sport == PORT_S1AP or sctp.dport == PORT_S1AP:
                    # sctp_data_list = ["%02X" % x for x in sctp.data]
                    chunk_1 = scp.data[0]
                    chunk_2 = scp.data[1]
                    self.protocol = 'S1AP'
                    # self.message_code =
                    # self.message_code = Packet.get_diam_message_code(int(tcp_data_list[0], 16))
                    # self.message_text = messages['S1AP'][self.message_code]
                    print('This is S1AP message {}'.format(self.message_text))

        except KeyError as ex:
            # return 'KeyError: {}'.format(ex)
            raise KeyError('Message type {} not implemented'.format(upd_data_list[1]))
            # print('KeyError: {}'.format(ex))

        except Exception as ex:
            print('Exception: {}'.format(ex))

    def __str__(self):
        """
        String to print when calling print()
        :return:
        """
        # return '\tPkt num: {}\n\tSource: {}\n\tDestination: {}\n\tGTP version {}\n\tGTP message {}'. \
        #     format(self.num, Packet.inet_to_str(self.src_ip), Packet.inet_to_str(self.dst_ip), self.gtp_v, self.message_text)
        return '\tPkt num: {}\n\tSource: {}\n\tDestination: {}\n\tProtocol: {}'. \
            format(self.num, Packet.inet_to_str(self.src_ip), Packet.inet_to_str(self.dst_ip), self.protocol)

    @staticmethod
    def get_diam_message_code(flags):
        """
        Extract the Diameter message code from the contents of Flags field
        :param flags:
        :return:
        """
        f1b = Packet.extract(flags, 1, 0)

        return f1b


    @staticmethod
    def get_gtp_version(flags):
        """
        Determine the GTP version from the contents of Flags field
        :param flags:
        :return:
        """
        f3b = Packet.extract(flags, 3, 0)

        return f3b

        # if flags == '32':
        #     return 1
        # elif flags == '48':
        #     return 2
        # else:
        #     return -1

    @staticmethod
    def extract(num, k, p):
        """
        Extract k bits from p position
        :param num: Number
        :param k: Number of bits to extract
        :param p: Initial position
        :return: Extracted value as integer
        """
        binary = format(num, '08b')

        # extr = ((1 << k) - 1) & (mybin >> (p - 1))
        # return extr
        # return ((1 << k) - 1) & (mybin >> (p - 1))

        # # convert number into binary first
        # binary = bin(num)
        #
        # # remove first two characters
        # binary = binary[2:]
        #
        # end = len(binary) - p
        # start = end - k + 1

        start = p
        end = p + k -1

        # extract k  bit sub-string
        kBitSubStr = binary[start: end + 1]

        # convert extracted sub-string into decimal again
        return int(kBitSubStr, 2)
        # print(int(kBitSubStr, 2))

    @staticmethod
    def mac_addr(address):
        """
        Convert a MAC address to a readable/printable string
        :param address: MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
        :return: Printable/readable MAC address
        """
        return ':'.join(["%02X" % x for x in address]).strip()

    @staticmethod
    def inet_to_str(inet):
        """
        Convert inet object to a string
        :param inet: inet network address
        :return: Printable/readable IP address
        """
        try:
            return socket.inet_ntoa(inet)
        except ValueError:
            sys.exit(2)


def autolabel(ax, rects, xpos='center'):
    """
    Attach a text label above each bar in *rects*, displaying its height.
    *xpos* indicates which side to place the text w.r.t. the center of
    the bar. It can be one of the following {'center', 'right', 'left'}.
    """
    xpos = xpos.lower()  # normalize the case of the parameter
    ha = {'center': 'center', 'right': 'left', 'left': 'right'}
    offset = {'center': 0.5, 'right': 0.57, 'left': 0.43}  # x_txt = x + w*off

    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width() * offset[xpos], 1.01 * height,
                '{}'.format(height), ha=ha[xpos], va='bottom')


def create_barchart_vlan(vlan_id, results):
    """
    Creates a plot of type bar chart to display number of messages by VLAN
    :param vlan_id:
    :param results:
    :return: Figure
    """

    global labels_gtp, messages

    sum_values = {}

    # Compute the number of messages of each type
    for k in results.keys():
        for m in results[k].keys():
            if m not in sum_values.keys():
                sum_values[m] = 0
            sum_values[m] += results[k][m]

    requests = []
    responses = []

    for v in messages['gtp'].keys():
        for i, m in enumerate(messages['gtp'][v]):
            if i % 2:
                responses.append(sum_values[(v, m)] if (v, m) in sum_values.keys() else 0)
            else:
                requests.append(sum_values[(v, m)] if (v, m) in sum_values.keys() else 0)

    # This is for plotting purpose
    ind = np.arange(len(labels_gtp))  # the x locations for the groups
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    fig.suptitle = vlan_id
    rects1 = ax.bar(ind - width / 2, requests, width, color='SkyBlue', label='Requests')
    rects2 = ax.bar(ind + width / 2, responses, width, color='IndianRed', label='Responses')

    # Add some text for labels_gtp, title and custom x-axis tick labels_gtp, etc.
    ax.set_ylabel('Number of messages')
    ax.set_title('VLAN id {0}'.format(vlan_id))
    ax.set_xticks(ind)
    ax.set_xticklabels(labels_gtp, rotation=45)
    ax.legend()

    autolabel(ax, rects1, "left")
    autolabel(ax, rects2, "right")

    # plt.show()

    return fig


def create_barchart_sum(sum_values):

    global labels_gtp, messages

    requests = []
    responses = []

    for v in messages['gtp'].keys():
        for i, m in enumerate(messages['gtp'][v]):
            if i % 2:
                responses.append(sum_values[(v, m)] if (v, m) in sum_values.keys() else 0)
            else:
                requests.append(sum_values[(v, m)] if (v, m) in sum_values.keys() else 0)

    # This is for plotting purpose
    ind = np.arange(len(labels_gtp))  # the x locations for the groups
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    fig.suptitle = "Sum Total"
    rects1 = ax.bar(ind - width / 2, requests, width, color='SkyBlue', label='Requests')
    rects2 = ax.bar(ind + width / 2, responses, width, color='IndianRed', label='Responses')

    # Add some text for labels_gtp, title and custom x-axis tick labels_gtp, etc.
    ax.set_ylabel('Number of messages')
    ax.set_title('Sum total')
    ax.set_xticks(ind)
    ax.set_xticklabels(labels_gtp, rotation=45)
    ax.legend()

    autolabel(ax, rects1, "left")
    autolabel(ax, rects2, "right")

    # plt.show()


def print_results(results, base):
    """
    Prints results from dictionaries stored in a JoinableQueue
    :param results: Object of type JoinableQueue
    :param base: Base name of the file being processed
    :return:
    """
    global dict_nodes
    global labels_gtp
    overall_values = {}

    curr_dt = datetime.datetime.now()
    curr_dt_str = curr_dt.strftime('%Y%m%d%H%M%S')

    # The PDF document
    pdf_pages = PdfPages('{}-analyzed-{}.pdf'.format(base, curr_dt_str))

    while not results.empty():
        d = results.get()
        for v in d.keys():
            print('VLAN id {}'.format(v))
            pdf_pages.savefig(create_barchart_vlan(v, d[v]))
            plt.close()
            for i in d[v].keys():
                # src = int2ip(i[0])
                # dst = int2ip(i[1])
                src = i[0]
                dst = i[1]
                if src in dict_nodes.keys():
                    src = dict_nodes[src]
                if dst in dict_nodes.keys():
                    dst = dict_nodes[dst]
                print("\t{}-{}".format(src, dst))
                for m in d[v][i]:
                    print("\t\t{}: {}".format(messages['gtp'][m[0]][m[1]], d[v][i][m]))
                    if m not in overall_values.keys():
                        overall_values[m] = 0
                    overall_values[m] += d[v][i][m]

    pdf_pages.savefig(create_barchart_sum(overall_values))
    plt.close()
    # Write the PDF document to the disk
    pdf_pages.close()


# def process_pcap(pcap):
#     """
#     Process each pcap packet
#     :param pcap: dpkt pcap reader object (dpkt.pcap.Reader)
#     :return:
#     """
#     num = 1
#     for ts, pkt in pcap:
#         try:
#             p = Packet(pkt, ts, num)
#             print(p)
#         except KeyError as ex:
#             print(ex)
#         num += 1


def process_pcap(pcap, base):
    """
    Process a pcap file
    :param pcap: pcap file as read by pyshark module
    :param base: base name of the file being processed
    :return: None
    """
    # Establish communication queues
    tasks = {}
    packets_to_process = {}
    results = JoinableQueue()

    num = 1

    # for pkt in pcap:
    for ts, pkt in pcap:

        try:

            p = Packet(pkt, ts, num)

            # DEBUG
            print(p)

            # Key for different tasks is the tuple (vlan_id, protocol)
            # key = (p.vlan_id, p.protocol) if p.vlan_id else (-1, p.protocol)
            key = (p.vlan_id, p.protocol)

            # Create queues for the corresponding keys if they do not exist
            # if p.vlan_id not in packets_to_process.keys():
            #     packets_to_process[p.vlan_id] = JoinableQueue()
            if key not in packets_to_process.keys():
                packets_to_process[key] = JoinableQueue()

            # Create and start tasks for the corresponding VLAN if they do not exist
            # if p.vlan_id not in tasks.keys():
            #     print('Creating Analyzer for VLAN id {}'.format(p.vlan_id))
            #     tasks[p.vlan_id] = Analyzer(p.vlan_id, packets_to_process[p.vlan_id], results)
            #     tasks[p.vlan_id].start()
            if key not in tasks.keys():
                print('Creating Analyzer for tuple {}'.format(key))
                tasks[key] = Analyzer(key[0], key[1], packets_to_process[key], results)
                tasks[key].start()

            packets_to_process[key].put(p)

        except AttributeError as e:
            print('AttributeError: {0}'.format(e))

        except KeyError as e:
            print('KeyError: {0}'.format(e))

        num += 1

    # Add a poison pill for each consumer
    for j in tasks.keys():
        packets_to_process[j].put(None)

    # Wait for all of the tasks to finish
    for k in tasks.keys():
        packets_to_process[k].join()

    results.task_done()

    # Print results
    print_results(results, base)


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
        print(errmsg)
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
    # num_proc = cpu_count()

    if options.ifile:
        with open(options.ifile, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            base = os.path.splitext(os.path.basename(options.ifile))[0]
            process_pcap(pcap, base)

    print('...Finished')

    # Print time taken to process all packets
    print('It took {} seconds'.format(time() - ts))


""" Entry point """
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

