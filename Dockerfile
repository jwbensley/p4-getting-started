FROM p4lang/p4app:latest

RUN apt-get update && \
apt-get install --no-install-recommends -y \
git ca-certificates

RUN git clone https://github.com/p4lang/tutorials.git /tutorials
