# NetPlier

NetPlier is a tool for binary protocol reverse engineering. It takes network traces as input and infer the keywork by multiple sequence alignment and probabilistic inference. Please find the details in our paper: [NETPLIER: Probabilistic Network Protocol Reverse
Engineering from Message Traces](https://www.cs.purdue.edu/homes/ye203/pub/NDSS21a.pdf).

## Installation
- Install dependencies (python 3.6 or higher):
```bash
$ pip install -r requirements.txt
```
- Install `netzob`: [https://github.com/netzob/netzob.git](https://github.com/netzob/netzob.git)
- Install `mafft`: [https://mafft.cbrc.jp/alignment/software/](https://mafft.cbrc.jp/alignment/software/)

## Usage

Run NetPlier with the following command:
```bash
$ python main.py -i INPUT_FILE_PATH -o OUTPUT_DIR -t PROTOCOL_TYPE [Other Options]
```
e.g.:
```bash
$ python netplier/main.py -i data/dhcp_100.pcap -o tmp/dhcp -t dhcp 
```
Arguments:
- `-i`, `--input`: the filepath of input trace (required)
- `-o`, `--output_dir`: the folder for output files (default: `tmp/`)
- `-t`, `--type`: the type of the test protocol (for generating the ground truth)  
currently it supports `dhcp`, `dnp3`, `icmp`, `modbus`, `ntp`, `smb`, `smb2`, `tftp`, `zeroaccess`
- `-l`, `--layer`: the layer of the protocol (default: `5`)  
for the network layer protocol (e.g., `icmp`), it should be `3`
- `-m`, `--mafft`: the alignment mode of mafft, including `ginsi`(default), `linsi`, `einsi`  
refer to [mafft](https://mafft.cbrc.jp/alignment/software/algorithms/algorithms.html) for detailed features of each mode
- `-mt`, `--multithread`: using multithreading for alignment (default: `False`)
