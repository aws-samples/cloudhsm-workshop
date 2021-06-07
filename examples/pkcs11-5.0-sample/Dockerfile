FROM public.ecr.aws/amazonlinux/amazonlinux:2
RUN yum install -y make cmake gcc gcc-c++ openssl-devel wget unzip jq
RUN mkdir /app && mkdir /cloudhsm
COPY ./app app

RUN wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-mgmt-util-3.3.0-2.el7.x86_64.rpm -P /cloudhsm/ && yum install -y /cloudhsm/cloudhsm-mgmt-util-3.3.0-2.el7.x86_64.rpm
RUN wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-pkcs11-5.0.0-2.el7.x86_64.rpm -P /cloudhsm/ && yum install -y /cloudhsm/cloudhsm-pkcs11-5.0.0-2.el7.x86_64.rpm

RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && unzip "awscliv2.zip" && ./aws/install

WORKDIR /app
RUN rm -rf /cloudhsm && rm -rf build/ && mkdir build/
WORKDIR /app/build
RUN cmake .. && make

COPY ./run.sh run.sh

ENTRYPOINT /app/build/run.sh