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

import logging
import os

from netzob.Model.Vocabulary.Field import Field
from netzob.Model.Vocabulary.Types.Raw import Raw
#from netzob.all import *
#from netzob.Model.Vocabulary.Session import Session
#from netzob.Model.Vocabulary.Field import Field

from alignment import Alignment
from constraint.constraint import Constraint
from probabilistic_inference import ProbabilisticInference

class NetPlier:
    def __init__(self, messages, direction_list=None, output_dir='tmp/', mode='ginsi', multithread=False):
        self.messages = messages
        self.direction_list = direction_list
        self.output_dir = output_dir
        self.mode = mode
        self.multithread = multithread

        if not os.path.exists(self.output_dir):
            logging.debug("Folder {0} doesn't exist".format(self.output_dir))
            os.makedirs(self.output_dir)

    def execute(self):
        
        # Alignment
        # TODO: choose mode automatically
        msa = Alignment(messages=self.messages, output_dir=self.output_dir, mode=self.mode, multithread=self.multithread)
        #msa = Alignment(messages=self.messages, output_dir=self.output_dir, multithread=True)
        msa.execute()
        # exit()
        
        # Generate fields
        filepath_fields_info = os.path.join(self.output_dir, Alignment.FILENAME_FIELDS_INFO)
        self.fields, fid_list = self.generate_fields_by_fieldsinfo(filepath_fields_info)
        logging.debug("Number of keyword candidates: {}\nfid: {}".format(len(fid_list), fid_list))
        
        # Compute probabilities of observation constraints
        constraint = Constraint(messages=self.messages, direction_list=self.direction_list, fields=self.fields, fid_list=fid_list, output_dir=self.output_dir)
        
        pairs_p, pairs_size = constraint.compute_observation_probabilities()
        pairs_p_request, pairs_p_response = pairs_p
        pairs_size_request, pairs_size_response = pairs_size
        constraint.save_observation_probabilities(pairs_p_request, pairs_size_request, Constraint.TEST_TYPE_REQUEST)
        constraint.save_observation_probabilities(pairs_p_response, pairs_size_response, Constraint.TEST_TYPE_RESPONSE)
        
        # pairs_p_request, pairs_size_request = constraint.load_observation_probabilities(Constraint.TEST_TYPE_REQUEST)
        # pairs_p_response, pairs_size_response = constraint.load_observation_probabilities(Constraint.TEST_TYPE_RESPONSE)
        # print(pairs_p_request, pairs_size_request)
        # print(pairs_p_response, pairs_size_response)

        # Probabilistic inference
        pairs_p_all, pairs_size_all = self.merge_constraint_results(pairs_p_request, pairs_p_response, pairs_size_request, pairs_size_response)

        ffid_list = ["{0}-{0}".format(fid) for fid in fid_list] #only test same fid for both sides
        pi = ProbabilisticInference(pairs_p=pairs_p_request, pairs_size=pairs_size_request)
        fid_inferred = pi.execute(ffid_list)
        
        ## TODO: iterative
        ## TODO: format inference
        
        return fid_inferred

    # Generate fields from mafft results
    def generate_fields_by_fieldsinfo(self, filepath_fields_info):
        print("[++++++++] Generate fields")
        assert os.path.isfile(filepath_fields_info), "The fields info file doesn't exist"

        fid_list = list()
        fields_result = list()
        
        with open(filepath_fields_info) as f:
            line_list = f.readlines()
            for i, line in enumerate(line_list):
                typename, typesizemin, typesizemax, fieldtype = line.split()
                typeinfo = [typename, int(typesizemin), int(typesizemax)]
                fields_result.append(typeinfo)

                if fieldtype == 'D':
                    fid_list.append(i)

        fields = self.generate_fields(fields_result)
        logging.debug("Number of fields: {0}".format(len(fields)))

        return fields, fid_list

    ## Generate fields
    def generate_fields(self, fields_result):
        fields = list()
        for typeinfo in fields_result:
            if typeinfo[0] == "Raw":
                field = Field(Raw(nbBytes=(typeinfo[1]//8, typeinfo[2]//8)))
                fields.append(field)
            else:
                logging.error("Field type is not Raw")

        return fields

    def merge_constraint_results(self, pairs_p_request, pairs_p_response, pairs_size_request, pairs_size_response):
        pairs_p_all, pairs_size_all = dict(), dict()
        assert pairs_p_request.keys() == pairs_p_response.keys(), \
            "pairs_p_request/pairs_p_response do not have the same fid pairs"

        for fid in pairs_p_request:
            pairs_p_all[fid] = list()
            for i in range(len(pairs_p_request[fid])):
                pairs_p_all[fid].append(pairs_p_request[fid][i] + pairs_p_response[fid][i])
                '''
                if i == 1: # not merge rc
                    pairs_p_all[fid].append(pairs_p_request[fid][i])
                else:
                    pairs_p_all[fid].append(pairs_p_request[fid][i] + pairs_p_response[fid][i])
                '''
            pairs_size_all[fid] = pairs_size_request[fid] + pairs_size_response[fid]

        return pairs_p_all, pairs_size_all
