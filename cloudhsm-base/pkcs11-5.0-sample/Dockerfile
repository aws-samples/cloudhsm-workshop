FROM public.ecr.aws/amazonlinux/amazonlinux:2

RUN yum update -y && yum install -y make cmake gcc gcc-c++ openssl-devel wget unzip jq

RUN mkdir /app && mkdir /cloudhsm
COPY ./app /app

# Install appropriate PKCS #11 library
RUN wget "https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-pkcs11-latest.el7.$(uname -m).rpm" -O /cloudhsm/cloudhsm-pkcs11.rpm && \
    yum install -y /cloudhsm/cloudhsm-pkcs11.rpm && \
    rm -f /cloudhsm/cloudhsm-pkcs11.rpm && \
    yum clean all

# Download and install AWS CLI
RUN wget "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -O "awscliv2.zip" && \
    unzip "awscliv2.zip" && \
    ./aws/install && \
    rm awscliv2.zip && \
    rm -rf aws

WORKDIR /app
RUN mkdir build
WORKDIR /app/build
RUN cmake .. && make

COPY ./run.sh run.sh
RUN chmod +x ./run.sh

ENTRYPOINT ["/app/build/run.sh"]
