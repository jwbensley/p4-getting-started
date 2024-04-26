#FROM p4lang/p4app:latest
# Use an Ubuntu container instead of the P4 container because p4-utils won't install on there.
FROM ubuntu:22.04

RUN apt-get update && \
DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y gnupg2 wget ca-certificates git python3-pip inetutils-ping tcpdump && \
apt-get clean && \
rm -rf /var/lib/apt/lists/*

RUN wget -nv https://download.opensuse.org/repositories/home:/p4lang/xUbuntu_22.04/Release.key -O Release.key && \
apt-key add - < Release.key
RUN echo "deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_22.04/ /" > /etc/apt/sources.list.d/home:p4lang.list && \
curl -fsSL "https://download.opensuse.org/repositories/home:p4lang/xUbuntu_22.04/Release.key" | gpg --dearmor | tee /etc/apt/trusted.gpg.d/home_p4lang.gpg > /dev/null

RUN apt-get update && \
DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y p4lang-p4c

RUN git clone https://github.com/nsg-ethz/p4-utils.git /p4-utils && \
cd /p4-utils/ && \
pip install -e "."

COPY ./examples /examples

RUN pip install -r /examples/requirements.txt

WORKDIR /examples/
