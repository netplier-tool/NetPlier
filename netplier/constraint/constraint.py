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

import os
import logging
import copy
import collections
import gc

from netzob.Model.Vocabulary.Symbol import Symbol
from netzob.Model.Vocabulary.Field import Field
from netzob.Model.Vocabulary.Types.Raw import Raw
#from netzob.Import.PCAPImporter.all import *
#from netzob.Model.Vocabulary.Session import Session

from processing import Processing
from alignment import Alignment
from constraint.message_similarity import MessageSimilarity
from constraint.remote_coupling import RemoteCoupling

class Constraint:
    TEST_TYPE_REQUEST = 0
    TEST_TYPE_RESPONSE = 1
    #FILENAME_P_REQUEST = "prob_request.txt"
    #FILENAME_P_RESPONSE = "prob_response.txt"

    def __init__(self, messages, direction_list, fields, fid_list, output_dir='tmp/'):
        self.messages = messages
        self.direction_list = direction_list
        self.fields = fields
        self.fid_list = fid_list
        self.output_dir = output_dir

    def compute_observation_probabilities(self):
        print("[++++++++] Compute probabilities of observation constraints")
        messages_aligned = Alignment.get_messages_aligned(self.messages, os.path.join(self.output_dir, Alignment.FILENAME_OUTPUT_ONELINE))
        messages_request, messages_response = Processing.divide_msgs_by_directionlist(self.messages, self.direction_list)
        messages_request_aligned, messages_response_aligned = Processing.divide_msgs_by_directionlist(messages_aligned, self.direction_list)

        fid_list_request = self.filter_fields(self.fields, self.fid_list, messages_request_aligned)
        fid_list_response = self.filter_fields(self.fields, self.fid_list, messages_response_aligned)
        logging.debug("request candidate fid: {}\nresponse candidate fid: {}".format(fid_list_request, fid_list_response))

        # compute matrix of similarity scores
        constraint_m_request, constraint_m_response = MessageSimilarity(messages = messages_request_aligned), MessageSimilarity(messages = messages_response_aligned)
        constraint_m_request.compute_similarity_matrix()
        constraint_m_response.compute_similarity_matrix()
        
        # the observation prob of each cluster: {fid: the list of observation probabilities ([pm,ps,pd,pv])} 
        cluster_p_request, cluster_p_response = dict(), dict() 
        # the size of each cluster
        cluster_size_request, cluster_size_response = dict(), dict()
        # the observation prob of each cluster pair: {fid-fid: [,]}
        pairs_p_request, pairs_p_response = dict(), dict()
        pairs_size_request, pairs_size_response = dict(), dict()

        for fid_request in fid_list_request:
            logging.info("[++++] Test Request Field {0}-*".format(fid_request))

            # merge other fields
            fields_merged_request = self.merge_nontest_fields(self.fields, fid_request)
            fid_merged_request = 0 if fid_request == 0 else 1

            # generate clusters
            symbols_request_aligned = self.cluster_by_field(fields_merged_request, messages_request_aligned, fid_merged_request)
            # change symbol names
            symbols_request_aligned = self.change_symbol_name(symbols_request_aligned)

            # compute prob of m,s,d,v
            cluster_p_request[fid_request] = list()
            cluster_p_request[fid_request].append(constraint_m_request.compute_constraint_message_similarity(symbols_request_aligned))
            cluster_p_request[fid_request].append(self.compute_constraint_structure(symbols_request_aligned))
            cluster_p_request[fid_request].append(self.compute_constraint_dimension(symbols_request_aligned))
            cluster_p_request[fid_request].append(self.compute_constraint_value(symbols_request_aligned))
            cluster_size_request[fid_request] = [len(s.messages) for s in symbols_request_aligned.values()]

            for fid_response in fid_list_response:
                #if fid_request != fid_response:
                #    continue
                logging.debug("[++] Test Response Field {0}-{1}".format(fid_request, fid_response))

                # merge other fields
                fields_merged_response = self.merge_nontest_fields(self.fields, fid_response)
                fid_merged_response = 0 if fid_response == 0 else 1

                # generate clusters
                symbols_response_aligned = self.cluster_by_field(fields_merged_response, messages_response_aligned, fid_merged_response)
                # change symbol names
                symbols_response_aligned = self.change_symbol_name(symbols_response_aligned)

                # compute prob of m,s,d,v
                if fid_response not in cluster_p_response:
                    cluster_p_response[fid_response] = list()
                    cluster_p_response[fid_response].append(constraint_m_response.compute_constraint_message_similarity(symbols_response_aligned))
                    cluster_p_response[fid_response].append(self.compute_constraint_structure(symbols_response_aligned))
                    cluster_p_response[fid_response].append(self.compute_constraint_dimension(symbols_response_aligned))
                    cluster_p_response[fid_response].append(self.compute_constraint_value(symbols_response_aligned))
                    cluster_size_response[fid_response] = [len(s.messages) for s in symbols_response_aligned.values()]

                # print msg numbers of each cluster
                logging.debug("Number of request symbols: {0}".format(len(symbols_request_aligned.values())))
                for s in symbols_request_aligned.values():
                    logging.debug("  Symbol {0} msgs numbers: {1}".format(str(s.name), len(s.messages)))
                logging.debug("Number of response symbols: {0}".format(len(symbols_response_aligned.values())))
                for s in symbols_response_aligned.values():
                    logging.debug("  Symbol {0} msgs numbers: {1}".format(str(s.name), len(s.messages)))

                # compute remote coupling probabilities
                rc = RemoteCoupling(messages_all=messages_aligned, symbols_request=symbols_request_aligned, symbols_response=symbols_response_aligned, direction_list=self.direction_list)
                rc.compute_pairs_by_directionlist()
                fid_pair = "{}-{}".format(fid_request, fid_response)
                p_r_request = rc.compute_constraint_remote_coupling(RemoteCoupling.TEST_TYPE_REQUEST)
                p_r_response = rc.compute_constraint_remote_coupling(RemoteCoupling.TEST_TYPE_RESPONSE)

                logging.debug("[+] Observation Prob Results for pairs {}".format(fid_pair))
                p_m, p_s, p_d, p_v = cluster_p_request[fid_request][0], cluster_p_request[fid_request][1], cluster_p_request[fid_request][2], cluster_p_request[fid_request][3]
                logging.debug("Request:\nPm: {0}\nPr: {1}\nPs: {2}\nPd: {3}\nPv: {4}".format(p_m, p_r_request, p_s, p_d, p_v))
                pairs_p_request[fid_pair] = [p_m, p_r_request, p_s, p_d, p_v]
                pairs_size_request[fid_pair] = cluster_size_request[fid_request]
                
                p_m, p_s, p_d, p_v = cluster_p_response[fid_response][0], cluster_p_response[fid_response][1], cluster_p_response[fid_response][2], cluster_p_response[fid_response][3]
                logging.debug("Response:\nPm: {0}\nPr: {1}\nPs: {2}\nPd: {3}\nPv: {4}".format(p_m, p_r_response, p_s, p_d, p_v))
                pairs_p_response[fid_pair] = [p_m, p_r_response, p_s, p_d, p_v]
                pairs_size_response[fid_pair] = cluster_size_response[fid_response]
                
                del rc
                del symbols_response_aligned #symbols
                del fields_merged_response
                gc.collect()
            del symbols_request_aligned
            del fields_merged_request
            gc.collect()

        pairs_p = [pairs_p_request, pairs_p_response]
        pairs_size = [pairs_size_request, pairs_size_response]

        return pairs_p, pairs_size

    def save_observation_probabilities(self, pairs_p, pairs_size, direction):
        filename = "prob_request.txt" if direction == Constraint.TEST_TYPE_REQUEST else "prob_response.txt"
        filepath = os.path.join(self.output_dir, filename)
        
        fid_pair_list = sorted(pairs_p.keys(), key= lambda x: (int(x.split('-')[direction]), int(x.split('-')[1 - direction])))
        # Write into files
        with open(filepath, 'w') as fout:
            for fid_pair in fid_pair_list:
                fout.write("{} ".format(fid_pair))

                # write Pm/r/s/d/v
                for p_list in pairs_p[fid_pair]:
                    for p in p_list[:-1]:
                        fout.write("{},".format(p))
                    fout.write("{} ".format(p_list[-1]))

                for n in pairs_size[fid_pair][:-1]:
                    fout.write("{},".format(n))
                fout.write("{} ".format(pairs_size[fid_pair][-1]))
                fout.write("\n")

    # read probabilities from file
    def load_observation_probabilities(self, direction):
        filename = "prob_request.txt" if direction == Constraint.TEST_TYPE_REQUEST else "prob_response.txt"
        filepath = os.path.join(self.output_dir, filename)
        assert os.path.exists(filepath), "File {0} doesn't exist".format(filepath)
        
        pairs_p, pairs_size = dict(), dict()

        with open(filepath) as f:
            for line in f.read().splitlines():
                fid_pair = line.split()[0]
                #fid_request = int(fid_list.split(",")[0])
                #fid_response = int(fid_list.split(",")[1])
                pairs_p[fid_pair] = list()
                for p_list in line.split()[1:-1]:
                    p_values = [float(p) for p in p_list.split(",")]
                    pairs_p[fid_pair].append(p_values)
                pairs_size[fid_pair] = [int(n) for n in line.split()[-1].split(",")]
                #print("fid {}: {}".format(fid, dict_sn_msgnum[fid]))

        return pairs_p, pairs_size

    # compute p_s
    # TODO: provide another method to align each cluster again
    def compute_constraint_structure(self, symbols):
        logging.debug("[+] Compute observation probabilities of structure coherence")
        sn_list = [str(s.name) for s in symbols.values()]

        # if there is ony one msg, then it is always 1.0
        dict_result = dict() 
        for s in symbols.values():
            # compute the num of gaps shared by all msgs
            num_gap_extra = 0
            for i in range(len(s.messages[0].data)):
                valuelist = [message.data[i] for message in s.messages]
                if len(set(valuelist)) == 1 and valuelist[0] == '-':
                    num_gap_extra += 1
            #print("Num Extra Gaps: {}".format(num_gap_extra))
            
            # compute ave num of gaps
            num_gap = 0 
            for message in s.messages:
                num_gap += (message.data.count("-") - num_gap_extra)

            num_gap_ave = num_gap / len(s.messages)
            percentage_gap = num_gap_ave / (len(s.messages[0].data) - num_gap_extra)
            dict_result[s.name] = [1 - percentage_gap, num_gap_ave]

        p_s = list()
        for s in sn_list:
            p_s.append(dict_result[s][0])

        return p_s

    # compute p_d
    def compute_constraint_dimension(self, symbols):
        logging.debug("[+] Compute observation probabilities of dimension")
        num_smallsymbols = 0
        for s in symbols.values():
            if len(s.messages) <= 2:
                num_smallsymbols += 1

        p = 1 - num_smallsymbols / len(symbols.values())
        p_d = [p]

        return p_d

    # compute p_v
    def compute_constraint_value(self, symbols):
        # TODO: may not need it
        if len(symbols.values()) == 1:
            p = -1
        else:
            p = 1
        p_v= [p]

        return p_v

    """ Processing Func
    """
    # eliminate impossible fileds
    def filter_fields(self, fields, fid_list, messages):
        logging.debug("[++++] Filter Fields")
        fid_list_new = list()
        for fid in fid_list:
            logging.debug("\n[+] Test Field_{0}".format(fid))

            il, ir = 0, 0
            for i in range(fid):
                il += fields[i].domain.dataType.size[1] // 8
            ir = il + (fields[fid].domain.dataType.size[1] // 8)

            # -1: the test field is too long
            if (fields[fid].domain.dataType.size[1] // 8) > 10:
                logging.debug("The tested field is too long.")
                continue

            # -2: message is too short to have field[fid]
            if self.has_short_msg(messages, ir):
                ##Check if the symbol_ntest side has field_merged.
                ##If the fields is empty, there will be InvalidParsingPathException error in computeFGP-clusterByKeyField
                logging.debug("Some messages doesn't have this field.")
                continue

            #-3: too many symbols (>60%)
            # TODO
            f_values = [message.data[il:ir] for message in messages]
            percentage = len(messages) / len(set(f_values))
            if percentage < 1.5 or len(set(f_values)) > 50: # TODO: save time, but may cause error in small data set (modbus_100)
                logging.debug("There are too many symbols")
                continue

            fid_list_new.append(fid)

        #print(len(fid_list_new), fid_list_new)
        return fid_list_new

    def has_short_msg(self, messages, length):
        for message in messages:
            if len(message.data) <= length:
                return True
        return False

    # merge other fields that are not tested in this run
    def merge_nontest_fields(self, fields_origin, fid):
        logging.debug("[+] Merge Fields")
        fields_merged = list()
        fields = copy.deepcopy(fields_origin)
        fsize_total = 0
        for i in range(len(fields)):
            typename = fields[i].domain.dataType.typeName
            if typename != "Raw":
                logging.error("Field type is not Raw")
            typesize = fields[i].domain.dataType.size[1]
            # print(i, fid, typesize, type(typesize))

            if i == fid:
                if fsize_total > 0:
                    field = Field(Raw(nbBytes=fsize_total//8))
                    fields_merged.append(field)
                    fsize_total = 0
                if fid != (len(fields) - 1):    
                    field = Field(Raw(nbBytes=typesize//8))
                    fields_merged.append(field)
                    field = Field()
                    fields_merged.append(field)
                else:
                    if type(typesize).__name__ == 'NoneType':
                        field = Field()
                    else:
                        field = Field(Raw(nbBytes=typesize//8))
                    fields_merged.append(field)
                break
            else:
                fsize_total += typesize         

        return fields_merged

    def cluster_by_field(self, fields, messages, fid_merged):
        logging.debug("[+] Generate Clusters")
        if fid_merged == 0:
            il = 0
            ir = fields[0].domain.dataType.size[1] // 8
        elif fid_merged == 1:
            il =fields[0].domain.dataType.size[1] // 8
            ir = il + (fields[1].domain.dataType.size[1] // 8)
        else:
            logging.error("Error: fid_merged should be 0 or 1")

        f_values = [message.data[il:ir] for message in messages]

        dict_fv_i = dict()
        for i,fv in enumerate(f_values):
            if fv not in dict_fv_i:
                dict_fv_i[fv] = list()
            dict_fv_i[fv].append(i)

        symbols = collections.OrderedDict()
        for fv in dict_fv_i:
            s = Symbol(name=fv, messages=[messages[i] for i in dict_fv_i[fv]])
            symbols[fv] = s

        return symbols

    def change_symbol_name(self, symbols):
        logging.debug("[+] Change symbol names")
        for keyFieldName, symbol in symbols.items():
            if type(keyFieldName).__name__ == "bytes":
                keyFieldName = binascii.unhexlify(keyFieldName)
                keyFieldName = keyFieldName.hex()
                symbol.name = str(keyFieldName)
            else:
                symbol.name = keyFieldName
            if len(symbol.name) > 40:
                md5 = hashlib.md5()
                md5.update(symbol.name.encode('utf-8'))
                symbol.name = str(md5.hexdigest())
        return symbols
