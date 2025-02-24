FROM public.ecr.aws/lambda/python:3.13

RUN dnf update -y && dnf install zip -y && dnf clean all

RUN pip3 --version & pip3 install boto3 --no-cache-dir

# Detect architecture and install cryptography package
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
        "x86_64")  PLATFORM="manylinux2014_x86_64" ;; \
        "aarch64") PLATFORM="manylinux2014_aarch64" ;; \
        *)         echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac && \
    echo "Detected architecture: $ARCH" && \
    echo "Installing cryptography for $PLATFORM" && \
    pip3 install \
        --platform $PLATFORM \
        --implementation cp \
        --only-binary=:all: --upgrade \
        --target /var/task \
        cryptography --no-cache-dir

COPY lambda_function.py /var/task

CMD [ "lambda_function.handler" ]
