import logging
import copy
import struct
from netzob.Import.PCAPImporter.all import *
from netzob.Model.Vocabulary.Session import Session

class Processing:
    MAX_LEN = 500 #100 // reduce the time for MSA

    def __init__(self, filepath, protocol_type=None, layer=5, messages=None):
        self.filepath = filepath
        self.protocol_type = protocol_type
        self.layer = layer
        self.messages = messages
        self.direction_list = list()

        if self.protocol_type:
            assert self.protocol_type in ['dhcp', 'dnp3', 'icmp', 'modbus', 'ntp', 'smb', 'smb2', 'tftp', 'zeroaccess'], 'the protocol_type is unknown'
        self.import_messages()
        self.get_msgs_directionlist()

    ## import msg
    ## protocol_type: dhcp, dnp3, icmp, modbus, ntp, smb, smb2, tftp, zeroaccess
    def import_messages(self):
        print("[++++++++] Import messages")
        # ICMP: layer = 3
        if self.protocol_type == 'icmp':
            self.layer = 3
        messages = PCAPImporter.readFile(filePath=self.filepath, importLayer=self.layer).values()

        ## Filter messages
        # extract from IP msgs
        if self.protocol_type == "icmp":
            for message in messages:
                len_header = message.data[0] & 0x0000000f
                startIndex = len_header * 4 #*32/8
                message.data = message.data[startIndex:]
        # in mb2, some msgs contain more than one mbtcp
        elif self.protocol_type == 'modbus':
            for i, message in enumerate(messages):
                length = int.from_bytes(message.data[4:4+2], byteorder='big', signed=True)
                if len(message.data) != length + 6:
                    message.data = message.data[:length+6]
        elif self.protocol_type == 'smb':
            for message in messages[::-1]:
                # delete not smb msgs
                if message.data[4:8].hex() != "ff534d42":
                    messages.remove(message)
                if len(message.data) > 500:
                    message.data = message.data[:500]
        elif self.protocol_type == 'smb2':
            for message in messages[::-1]:
                if message.data[4:8].hex() != "fe534d42":
                    messages.remove(message)
                if len(message.data) > 500:
                    message.data = message.data[:500]
        elif self.protocol_type == 'zeroaccess':
            for message in messages:
                message.data = self.decrypt_za_msg(message.data)

        # MAX_LEN = 500 
        for message in messages:
            if len(message.data) > Processing.MAX_LEN:
                message.data = message.data[:Processing.MAX_LEN]

        self.messages = messages

    def decrypt_za_msg(self, messagedata_encrypted):
        crc32 = struct.unpack("<I", messagedata_encrypted[0:4])[0]
        if crc32 == 0:
            return messagedata_encrypted

        key = 0x66747032
        result = []
        for i in range(0, len(messagedata_encrypted), 4):
            if (i + 4) >= len(messagedata_encrypted):
                break
            sub_data = struct.unpack("<I", messagedata_encrypted[i:i+4])[0]
            xored_subdata = sub_data ^ key
            decrpted_data = struct.pack("<I", xored_subdata)
            result.append(decrpted_data.hex())
            key = ((key << 1) & 0xffffffff | key >> 31)
        messagedata_decrypted = ''.join(result)
        
        return bytes.fromhex(messagedata_decrypted)

    ## generate direction list
    def get_msgs_directionlist(self):
        assert self.messages is not None, 'the messages could not be None'

        if not self.protocol_type or self.protocol_type == "tftp":
            direction_list = self.get_msgs_directionlist_by_sessions()
        else: ## get the direction by specification
            direction_list = list()
            for message in self.messages:
                d = self.get_msg_direction_by_specification(message)
                if d != 0 and d != 1:
                    logging.error("Error: GetMsgsDirectionlistBySpecification")
                direction_list.append(d)

        self.direction_list = direction_list

    def get_msgs_directionlist_by_sessions(self):
        dict_idtoi = dict()
        for i,message in enumerate(self.messages):
            dict_idtoi[message.id] = i

        direction_list = [-1]*len(self.messages)

        sessions = Session(self.messages)
        #print(sessions.getEndpointsList())
        #logging.info("Number of Sessions: {0}".format(len(sessions.getTrueSessions())))
        for session in sessions.getTrueSessions():
            messages_list = list(session.messages.values())
            messages_list = sorted(messages_list, key=lambda x:x.date)

            srcIP = messages_list[0].source
            for message in messages_list:
                if message.source == srcIP:
                    result = 0
                else:
                    result = 1
                direction_list[dict_idtoi[message.id]] = result

        return direction_list

    def get_msg_direction_by_specification(self, message):
        ##0: request; 1: response
        result = -1

        if self.protocol_type == "dhcp":
            #DHCP: original msgs data[0]; aligned msg (hex) data[1]
            if message.data[0] == 1:
                result = 0
            elif message.data[0] == 2:
                result = 1
            else:
                logging.error("Can not decide the direction of msg: {}".format(message.data[0]))
        elif self.protocol_type == "dnp3":
            f = (message.data[3] >> 7) & 0x01
            #1: from master
            #0: from outstation
            if f == 1:
                result = 0
            elif f == 0:
                result = 1
            else:
                logging.error("Can not decide the direction of msg: {}".format(f))
        elif self.protocol_type == "ftp":
            port_source, port_destination = message.source.split(":")[1], message.destination.split(":")[1]
            server_port = ["20", "21"]
            if port_source in server_port:
                result = 1
            elif port_destination in server_port:
                result = 0
            else:
                logging.error("Can not decide the direction of msg port: {} {}".format(message.source, message.destination))
        elif self.protocol_type == "icmp":
            ##9/10: not sure
            if message.data[0] in [8, 13, 15, 17, 10]:
                result = 0
            elif message.data[0] in [0, 3, 4, 5, 11, 12, 14, 16, 18, 9]:
                result = 1
            else:
                logging.error("Can not decide the direction of msg: {}".format(message.data[0]))
        elif self.protocol_type == "modbus":
            port_source, port_destination = message.source.split(":")[1], message.destination.split(":")[1]
            if port_source == "502":
                result = 1
            elif port_destination == "502":
                result = 0
            else:
                logging.error("Can not decide the direction of msg port: {} {}".format(message.source, message.destination))
        elif self.protocol_type == "ntp":
            f = message.data[0] & 0x07
            #1: symmetric active; 2: Symmetric Passive
            #3: client; 4: server;
            #5: broadcast server; 6: Broadcast Client
            if f == 1 or f == 3 or f == 5:
                result = 0
            elif f == 2 or f == 4 or f == 6:
                result = 1
            else:
                logging.error("Can not decide the direction of msg: {}".format(f))
        elif self.protocol_type == "smb":
            smb_flag = message.data[4+9]
            direction = smb_flag & 0x80
            if direction == 0:
                result = 0
            elif direction == 128:
                result = 1
            else:
                print("Can not decide the direction of msg: {}".format(direction))
        elif self.protocol_type == "smb2":
            #print(message.data[4+16:4+16+4].hex())
            smb_flag = struct.unpack("<I", message.data[4+16:4+16+4])[0]
            direction = smb_flag & 0x1
            #print(direction, type(direction))
            if direction == 0:
                result = 0
            elif direction == 1:
                result = 1
            else:
                logging.error("Can not decide the direction of msg: {}".format(direction))
        elif self.protocol_type == "zeroaccess":
            #g: 103; r: 114; n: 110
            if message.data[7] == 103:
                result = 0
            elif (message.data[7] == 114) or (message.data[7] == 110):
                result = 1
            else:
                logging.error("Can not decide the direction of msg: {}".format(message.data[7]))
        else:
            logging.error("The protocol_type is not unknown to detect direction")

        if result == -1:
            logging.error("Error: can't decide the drection: {0}".format(message.data))

        return result

    def print_dataset_info(self):
        assert self.protocol_type is not None, 'need the protocol_type to get dataset info'
        print("\n[++++++++] Get Dataset Info")

        ## Number of msgs
        messages_request, messages_response = Processing.divide_msgs_by_directionlist(self.messages, self.direction_list)
        print("Total msg number: {0}\nRequest msg number: {1}\nResponse msg number: {2}\n".format(len(self.messages), len(messages_request), len(messages_response)))

        ## True types info
        types_list_request = [self.get_true_keyword(message) for message in messages_request]
        types_list_response = [self.get_true_keyword(message) for message in messages_response]
        print("Request Symbols: {}".format(set(types_list_request)))
        print("Response Symbols: {}".format(set(types_list_response)))

        print("Number of request symbols: {0}".format(len(set(types_list_request))))
        for s in set(types_list_request):
            print("  Symbol {0} msgs numbers: {1}".format(s, types_list_request.count(s)))
        print("Number of response symbols: {0}".format(len(set(types_list_response))))
        for s in set(types_list_response):
            print("  Symbol {0} msgs numbers: {1}".format(s, types_list_response.count(s)))

        ## Session info
        messages = copy.deepcopy(self.messages)
        sessions = Session(messages)
        for i in range(len(self.direction_list)):
            data = [messages[i].data, self.direction_list[i]]
            messages[i].data = data
        num_of_session = len(sessions.getTrueSessions())
        print("\nNumber of Sessions: {0}".format(num_of_session))
        print("[++++++++] End\n")

    @staticmethod
    def divide_msgs_by_directionlist(messages, direction_list):
        messages_request = list()
        messages_response = list()
        for i in range(len(direction_list)):
            if direction_list[i] == 0:
                messages_request.append(messages[i])
            else:
                messages_response.append(messages[i])

        return messages_request,messages_response

    # get the true keyword defined by the specification
    def get_true_keyword(self, message):
        if self.protocol_type == "dhcp":
            kw = message.data[242:243]
        elif self.protocol_type == "dnp3":
            kw = message.data[12:13]
        elif self.protocol_type == "ftp":
            kw = re.split(" |-|\r|\n", message.data.decode())[0]
        elif self.protocol_type ==  "icmp":
            kw = message.data[0:2]
        elif self.protocol_type == "modbus":
            kw = message.data[7:8]
        elif self.protocol_type == "ntp":
            kw = message.data[0] & 0x07
        elif self.protocol_type == "smb":
            kw = message.data[4+4]
        elif self.protocol_type == "smb2":
            kw = struct.unpack("<H", message.data[4+12:4+12+2])[0]
        elif self.protocol_type == "tftp":
            kw = message.data[0:2]
        elif self.protocol_type == "zeroaccess":
            kw = message.data[4:8]
        else:
            logging.error("The TestName is not given known method for detecting direction.")

        if type(kw).__name__ == "bytes":
            kw = str(kw.hex())
    
        return kw
    