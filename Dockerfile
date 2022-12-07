# syntax=docker/dockerfile-upstream:master-labs
# Build with:
# DOCKER_BUILDKIT=1 docker build . -t netplier
FROM python:3.6.15-slim-buster

ADD --keep-git-dir=true https://github.com/netplier-tool/NetPlier.git /opt/netplier
ADD https://mafft.cbrc.jp/alignment/software/mafft_7.490-1_amd64.deb /tmp/mafft.deb

RUN dpkg -i /tmp/mafft.deb

RUN apt update && \
    apt -y install gcc g++ libpcap-dev

WORKDIR /opt/netplier

RUN grep numpy requirements.txt | xargs pip install && \
    pip install -r requirements.txt

RUN echo '#!/bin/bash\npython netplier/main.py $@' > /usr/bin/netplier && \
    chmod +x /usr/bin/netplier

ENTRYPOINT ["/usr/bin/netplier"] 
