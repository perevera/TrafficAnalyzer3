# -*- coding: utf-8 -*-
# !/usr/bin/env python

# import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np

messages = {'gtp': {1: 'EchoRequest', 2: 'EchoResponse',
                    16: 'CreatePDPContextRequest', 17: 'CreatePDPContextResponse',
                    18: 'UpdatePDPContextRequest', 19: 'UpdatePDPContextResponse',
                    20: 'DeletePDPContextRequest', 21: 'DeletePDPContextResponse'},
            'gtpv2': {32: 'CreateSessionRequest', 33: 'CreateSessionResponse',
                      34: 'ModifyBearerRequest', 35: 'ModifyBearerResponse',
                      36: 'DeleteSessionRequest', 37: 'DeleteSessionResponse',
                      170: 'ReleaseAccessBearersRequest', 171: 'ReleaseAccessBearersResponse'},
            'diameter': {1: 'Credit-Control Request', 0: 'Credit-Control Answer'},
            's1ap': {9: 'InitialContextSetupRequest', 3: 'InitialContextSetupRequest'},
            'gsm_map': {2: 'updateLocation', 3: 'cancelLocation', 7: 'insertSubscriberData',
                        8: 'deleteSubscriberData', 23: 'updateGprsLocation', 43: 'checkIMEI',
                        45: 'sendRoutingInfoForSM', 56: 'sendAuthenticationInfo'}}


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


def create_barchart(dictio, k, proto):
    """
    Creates a plot of type bar chart to display number of messages
    :param dictio:
    :return: Figure
    """

    global messages

    # sum_values = {}

    # Create the list of messages for the given protocol
    labels = []
    for v in messages[proto]:
        labels.append(messages[proto][v])

    # # Compute the number of messages of each type
    # for k in dictio:
    #     for m in dictio[k]:
    #         if m not in sum_values:
    #             sum_values[m] = [0, 0]
    #         sum_values[m][0] += dictio[k][m][0]
    #         sum_values[m][1] += dictio[k][m][1]
    #

    requests = []
    responses = []

    for m in messages[proto]:
        requests.append(dictio[k][m][0] if m in dictio[k] else 0)
        responses.append(dictio[k][m][1] if m in dictio[k] else 0)

    # This is for plotting purpose
    ind = np.arange(len(messages[proto]))  # the x locations for the groups
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    fig.suptitle = proto
    rects1 = ax.bar(ind - width / 2, requests, width, color='SkyBlue', label='Requests')
    rects2 = ax.bar(ind + width / 2, responses, width, color='IndianRed', label='Responses')

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Number of messages')
    ax.set_title('Key: {}'.format(k))
    ax.set_xticks(ind)
    ax.set_xticklabels(labels, rotation=15)
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


def print_results(dictio, proto, fname):
    """
    Prints results from dictionary
    :param dictio: Dictionary of messages
    :param proto: Protocol
    :param fname: Output file name
    :return:
    """
    overall_values = {}

    # curr_dt = datetime.datetime.now()
    # curr_dt_str = curr_dt.strftime('%Y%m%d%H%M%S')

    # The PDF document
    # pdf_pages = PdfPages('{}-analyzed-{}.pdf'.format(proto, suffix))
    pdf_pages = PdfPages(fname)
        
    for k in dictio:
        print('Key: {}'.format(k))
        pdf_pages.savefig(create_barchart(dictio, k, proto))
        plt.close()
        # # Compute overall values
        # for m in dictio[k]:
        #     print("\t\t{}: {}".format(messages[proto][m[0]][m[1]], d[v][i][m]))
        #     if m not in overall_values.keys():
        #         overall_values[m] = 0
        #     overall_values[m] += d[v][i][m]

    # pdf_pages.savefig(create_barchart_sum(overall_values))
    # plt.close()

    # Write the PDF document to the disk
    pdf_pages.close()
