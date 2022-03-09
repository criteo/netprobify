#
# HOWTO
#
# Build the image: docker build . -t netprobify
#
# Run the image: docker run -it --rm --network host -v "$PWD/config.yaml":/opt/netprobify/config.yaml --name "netprobify" netprobify
#

FROM python:3.9

RUN apt update
RUN apt install -y tcpdump
RUN apt clean

COPY netprobify /opt/netprobify/netprobify
COPY requirements /opt/netprobify/requirements
COPY netprobify_start.py /opt/netprobify/
COPY VERSION /opt/netprobify/

WORKDIR /opt/netprobify
RUN pip install -r requirements/netprobify.txt

# CLEANING

CMD [ "python", "/opt/netprobify/netprobify_start.py" ]
