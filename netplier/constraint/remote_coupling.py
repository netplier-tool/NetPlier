# This file is part of NetPlier, a tool for binary protocol reverse engineering.
# Copyright (C) 2021 Yapeng Ye

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

import copy
import logging

from netzob.Model.Vocabulary.Session import Session

class RemoteCoupling:
    TEST_TYPE_REQUEST = 0
    TEST_TYPE_RESPONSE = 1

    def __init__(self, messages_all, symbols_request, symbols_response, direction_list):
        self.messages_all = messages_all
        self.symbols_request = symbols_request
        self.symbols_response = symbols_response
        self.direction_list = direction_list

        self.pairs_request = dict()
        self.pairs_response = dict()

    # Use directionlist to check if it is valid session
    def compute_pairs_by_directionlist(self):
        logging.debug("[+] Compute request/respnse pairs info")

        symbolList_request = list(self.symbols_request.values())
        symbolList_response = list(self.symbols_response.values())
        symbolNameList_request = [str(s.name) for s in self.symbols_request.values()]
        symbolNameList_response = [str(s.name) for s in self.symbols_response.values()]

        # generate new messages
        messages = copy.deepcopy(self.messages_all)
        sessions = Session(messages)
        # lenofSession = len(sessions.getTrueSessions())
        # print("lenth of session: {0}".format(lenofSession))

        dict_mid_sn = dict()
        for s in self.symbols_request.values():
            sn = str(s.name)
            for message in s.messages:
                dict_mid_sn[message.id] = sn
        for s in self.symbols_response.values():
            sn = str(s.name)
            for message in s.messages:
                dict_mid_sn[message.id] = sn

        for i in range(len(self.direction_list)):
            data = [dict_mid_sn[messages[i].id], self.direction_list[i]]
            messages[i].data = data

        # count pair info
        dict_request, dict_response = dict(), dict()
        for sn in symbolNameList_request:
            dict_request[sn] = dict()
        for sn in symbolNameList_response:
            dict_response[sn] = dict()

        # TODO: improve
        for session in sessions.getTrueSessions():
            messages_list = list(session.messages.values())
            messages_list = sorted(messages_list, key=lambda x:x.date)

            #Check if it is invalid (the first is request)
            '''
            if messages_list[0].data[1] != 0:
                continue
            '''
            '''
            # Check if it is invalid (only request)
            srcIP_list = [message.source for message in messages_list]
            if len(set(srcIP_list)) == 1:
                #print("This session is invalid.")
                continue
            '''

            # Find the first request msg
            i_first_request_msg = -1
            for i,message in enumerate(messages_list):
                if message.data[1] == 0:
                    i_first_request_msg = i 
                    break
            if i_first_request_msg == -1:
                continue

            #requestSrcIP = str(messages_list[0].source)
            preRequestS = None  
            for message in messages_list[i_first_request_msg:]:
                sn = message.data[0]
                if message.data[1] == 0:
                    preRequestS = sn
                else:
                    if sn in dict_request[preRequestS]:
                        dict_request[preRequestS][sn] += 1
                    else:
                        dict_request[preRequestS][sn] = 1
                    if preRequestS in dict_response[sn]:
                        dict_response[sn][preRequestS] += 1
                    else:
                        dict_response[sn][preRequestS] = 1
        #print(dict_request)
        
        '''
        print("Request pairs info:")
        for key, dict_key in dict_request.items():
            print(repr(key))
            list_msgcount= sorted(dict_key.items(),key=lambda x:x[1],reverse=True)
            print(list_msgcount)

        print("Response pairs info:")
        for key, dict_key in dict_response.items():
            print(repr(key))
            list_msgcount= sorted(dict_key.items(),key=lambda x:x[1],reverse=True)
            print(list_msgcount)
        '''

        # compute pairs constraints results
        # method 1: use the lenth
        # method 2: use the proportion of the larger one
        for s in symbolNameList_request:
            # method 1
            # self.pairs_request[s] = 1 / len(dict_request[s])
            # method 2
            list_msgcount= sorted(dict_request[s].items(),key=lambda x:x[1],reverse=True)
            # print(list_msgcount)
            count_total = 0
            for item in list_msgcount:
                count_total += item[1]
            if len(list_msgcount) > 0:
                self.pairs_request[s] = list_msgcount[0][1] / count_total
            else:
                self.pairs_request[s] = 0
        for s in symbolNameList_response:
            # method 1
            #self.pairs_response[s] = 1 / len(dict_response[s])
            # method 2
            list_msgcount= sorted(dict_response[s].items(),key=lambda x:x[1],reverse=True)
            count_total = 0
            for item in list_msgcount:
                count_total += item[1]
            if len(list_msgcount) > 0:
                self.pairs_response[s] = list_msgcount[0][1] / count_total
            else:
                self.pairs_response[s] = 0
        '''
        print("Number of Request msg types: {0}".format(len(symbolNameList_request)))
        print(dict_result_request)
        print("Number of Response msg types: {0}".format(len(symbolNameList_response)))
        print(self.pairs_response)
        '''
        return 

    # compute p_r
    def compute_constraint_remote_coupling(self, direction):
        test_type = "request" if direction == RemoteCoupling.TEST_TYPE_REQUEST else "response"
        logging.debug("[+] Compute observation probabilities of remote coupling: {}".format(test_type))
        
        symbols = self.symbols_request if direction == RemoteCoupling.TEST_TYPE_REQUEST else self.symbols_response
        pairs = self.pairs_request if direction == RemoteCoupling.TEST_TYPE_REQUEST else self.pairs_response

        sn_list = [str(s.name) for s in symbols.values()]
        p_r = list()
        for s in sn_list:
            if pairs[s] > 0:
                p_r.append(pairs[s])
            else:
                p_r.append(-1)

        return p_r
    