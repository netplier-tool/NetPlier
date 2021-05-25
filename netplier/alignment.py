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

import subprocess
import os
import logging
import copy

"""
mafft mode: ginsi, linsi, einsi
details: https://mafft.cbrc.jp/alignment/software/algorithms/algorithms.html
"""
class Alignment:
    FILENAME_INPUT = "msa_input.fa"
    FILENAME_OUTPUT = "msa_output.txt"
    FILENAME_OUTPUT_ONELINE = "msa_output_oneline.txt"
    FILENAME_FIELDS_INFO = "msa_fields_info.txt"
    FILENAME_FIELDS_VISUAL = "msa_fields_visual.txt"

    def __init__(self, messages, output_dir='tmp/', mode='ginsi', multithread=False, ep=0.123):
        self.messages = messages
        self.output_dir = output_dir
        self.mode = mode
        self.multithread = multithread
        self.ep = ep
        '''
        self.nthread = nthread
        self.nthreadtb = nthreadtb
        self.nthreadit = nthreadit
        '''

        self.filepath_input = os.path.join(self.output_dir, Alignment.FILENAME_INPUT)
        self.filepath_output = os.path.join(self.output_dir, Alignment.FILENAME_OUTPUT)
        self.filepath_output_oneline = os.path.join(self.output_dir, Alignment.FILENAME_OUTPUT_ONELINE)
        self.filepath_fields_info = os.path.join(self.output_dir, Alignment.FILENAME_FIELDS_INFO)
        self.filepath_fields_visual = os.path.join(self.output_dir, Alignment.FILENAME_FIELDS_VISUAL)

    def execute(self):
        ## Generate msa input (with tilde)
        self.create_mafft_input_with_tilde()

        ## Execute Mafft
        self.execute_mafft()

        ## Change to oneline
        self.change_to_oneline()
        ## Remove tilde
        self.remove_character(self.filepath_output_oneline)

        ## Analyze fields
        self.generate_fields_info(self.filepath_output_oneline)
        self.generate_fields_visual_from_fieldsinfo()

    ## Create mafft input files
    # hex, without "~"
    def create_mafft_input(self):
        message_data_hex = list()
        for message in self.messages:
            message_data_hex.append(message.data.hex())

        with open(self.filepath_input, 'w') as f:
            for i, message in enumerate(message_data_hex):
                f.write(">{0}\n{1}\n".format(i, message))

    # hex, add "~" after each byte
    def create_mafft_input_with_tilde(self):
        message_data_hex = list()
        for message in self.messages:
            message_data_hex.append(message.data.hex())

        with open(self.filepath_input, 'w') as f:
            for i, message in enumerate(message_data_hex):
                message_space = '~'.join(message[j:j+2] for j in range(0, len(message), 2))
                f.write(">{0}\n{1}\n".format(i, message_space))
    
    def execute_mafft(self):
        print("[++++++++] Execute Alignment")

        assert self.mode in ["ginsi", "linsi", "einsi"], "the mafft mode should be ginsi, linsi, or einsi"

        if not self.multithread:
            cmd = f"mafft-{self.mode} --inputorder --text --ep {self.ep} --quiet {self.filepath_input} > {self.filepath_output}"
        else:
            cmd = f"mafft-{self.mode} --thread -1 --inputorder --text --ep {self.ep} --quiet {self.filepath_input} > {self.filepath_output}"
            #cmd = f"mafft-{self.mode} --thread {self.nthread} --threadtb {self.nthreadtb} --threadit {self.nthreadit} --inputorder --text --ep {self.ep} {self.filepath_input} > {self.filepath_output}"
        logging.debug("mafft cmd: {}".format(cmd))
        
        #run mafft
        result = subprocess.check_output(cmd, shell=True)

    ## process alignment results files
    def change_to_oneline(self):
        logging.debug("[+] Change to oneline")

        assert os.path.isfile(self.filepath_output), "The msa output file doesn't exist"

        isfirstline = True
        with open(self.filepath_output) as f:
            with open(self.filepath_output_oneline, 'w') as fout:
                for line in f.read().splitlines():
                    if line.startswith('>'):
                        if isfirstline:
                            isfirstline = False
                        else:
                            fout.write("\n")
                    else:
                        fout.write("{0}".format(line))

    def remove_character(self, filepath):
        logging.debug("[+] Remove character")

        assert os.path.isfile(filepath), "The file doesn't exist: {}".format(filepath)

        with open(filepath) as f:
            linelist = f.read().splitlines()

        results = [list() for i in range(len(linelist))]

        for i in range(len(linelist[0])):
            isToDelete = True
            for line in linelist:
                if line[i] != '-' and line[i] != '~':
                    isToDelete = False
                    break
            if not isToDelete:
                for j,line in enumerate(linelist):
                    #print("{0} {1}".format(i, j))
                    results[j].append(line[i])

        with open(filepath, 'w') as fout:
            for line in results:
                fout.write("{0}\n".format(''.join(line)))

    ## Analyze fields
    def generate_fields_info(self, filepath_input):
        logging.debug("[+] Generate fields info")
        
        assert os.path.isfile(filepath_input), "The file doesn't exist: {}".format(filepath_input)

        with open(filepath_input) as f:
            linelist = f.read().splitlines()

        length_message = len(linelist[0])

        ## Only record fields info
        results_fields = list()

        i = 0
        isLastStatic = False
        while i < length_message:
            offset = 2
            while i + offset <= length_message:
                valuelist = [line[i:i+offset] for line in linelist]
                if not self.has_even_number_of_bytes(valuelist):
                    offset += 1
                    continue
                else:
                    break
            if not len(set(valuelist)) == 1:
                if self.is_variable_field(valuelist):
                    fields_info = [offset, 'V']
                else:
                    fields_info = [offset, 'D']
                results_fields.append(fields_info)
                isLastStatic = False
            else:
                if isLastStatic:
                    results_fields[-1][0] += offset
                else:
                    fields_info = [offset, 'S']
                    results_fields.append(fields_info)
                isLastStatic = True

            i = i + offset
        logging.debug("Number of fields: {0}".format(len(results_fields)))

        with open(self.filepath_fields_info, 'w') as fout:
            for fields_info in results_fields:
                fout.write("Raw 0 {0} {1}\n".format(fields_info[0]*8, fields_info[1]))

    def has_even_number_of_bytes(self, valuelist):
        for value in valuelist:
            value_string = ''.join(value)
            if len(value_string.replace("-", "")) % 2 != 0:
                return False
        return True

    def is_variable_field(self, valuelist):
        for value in valuelist:
            if '-' in value:
                return True
        return False

    # from fields_info
    def generate_fields_visual_from_fieldsinfo(self):
        ## get fileds_info
        fields_info = self.get_fields_info()
        #print(fields_info)

        assert os.path.isfile(self.filepath_output_oneline), "The msa output oneline file doesn't exist"
        with open(self.filepath_output_oneline) as f:
            messages_data_mafft = f.read().splitlines()

        with open(self.filepath_fields_visual, 'w') as fout:
            for messages_data in messages_data_mafft:
                fields_value = list()
                pos_list = sorted(list(fields_info.keys()))
                pos_start = 0
                for i,pos_end in enumerate(pos_list):
                    fields_value.append(messages_data[pos_start:pos_end])
                    pos_start = pos_end
                fields_value.append(messages_data[pos_start:])
                fout.write("{0}\n".format(' '.join(fields_value)))

    # read fileds info from saved files
    def get_fields_info(self):
        assert os.path.isfile(self.filepath_fields_info), "The fields info file doesn't exist"

        fields_info = dict() #pos:type
        pos = 0
        with open(self.filepath_fields_info) as f:
            line_list = f.readlines()
            for i, line in enumerate(line_list):
                typename, typesizemin, typesizemax, fieldtype = line.split()
                pos += int(typesizemax) // 8
                fields_info[pos] = fieldtype

        return fields_info

    @staticmethod
    def get_messages_aligned(messages, filepath_output_oneline):
        assert os.path.isfile(filepath_output_oneline), "The msa output oneline file doesn't exist"

        messages_aligned = copy.deepcopy(messages)
        with open(filepath_output_oneline) as f:
            messages_aligned_data = f.read().splitlines()

        for i in range(len(messages_aligned)):
            messages_aligned[i].data = messages_aligned_data[i]

        return messages_aligned
