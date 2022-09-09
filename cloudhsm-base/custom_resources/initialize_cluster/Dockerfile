FROM public.ecr.aws/amazonlinux/amazonlinux:2022

RUN yum update -y \
    && yum install zip -y \
    && python3 -m ensurepip --upgrade
   
RUN pip3 install \
    --platform manylinux2010_x86_64 \
    --implementation cp \
    --python 3.9 \
    --only-binary=:all: --upgrade \
    --target "${LAMBDA_TASK_ROOT}" \
    cryptography

COPY lambda_function.py ${LAMBDA_TASK_ROOT}

CMD [ "lambda_function.handler" ] 