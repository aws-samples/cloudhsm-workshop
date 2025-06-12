# AWS CloudHSM Workshop

This repo contains the code for automatic deployment of resources used in the advanced section of the CloudHSM Workshop.

## Recent Changes

### Windows Systems Manager QuickSetup Implementation

The Windows instance management has been upgraded to use AWS Systems Manager QuickSetup for default host management with Fleet Manager enabled. This implementation replaces the previous custom approach that used direct SSM service settings.

Key improvements include:
- Standardized Windows instance management following AWS best practices
- Fleet Manager enabled for simplified Windows instance management
- Basic inventory collection for better visibility
- Targeting based on instance tags ('OS:Windows')

For detailed information on the implementation, see the [Windows SSM Management Documentation](docs/windows-ssm-management.md).

## Architecture

The CloudHSM workshop deploys several key components:
- CloudHSM cluster in a custom VPC
- Windows Server for Windows-specific CloudHSM integrations
- ECS containers for PKCS#11 sample applications
- Systems Manager configurations for instance management

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
