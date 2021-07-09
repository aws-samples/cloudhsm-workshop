# AWS CloudHSM Workshop  

This repo contains the code for automatic deployment of resources used in the advanced section of the CloudHSM Workshop.

Before deploying the CDK Stack, dependencies must be installed for the `initialize_cluster` lambda function.

```
cd ./custom_resources/initialize_cluster/
pip3 install -r requirements.txt -t ./dependencies
```

Note: If the host system is not `Linux` the lambda function will fail as the binary installed will not match the runtime environment in the lambda function. In such case, you can use a `Linux` machine (such as Cloud9) to create the dependencies and manually added them in inside a new folder in: 

`./custome_resources/initilize_cluster/dependencies`

Instructions for how to deploy the stack can be found in the pre-requisite section of the Workshop.

### License

This library is licensed under the MIT-0 License. See the LICENSE file.