# Required Installation of AWS CLI (In my case, it was Windows)
https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

### Direct Download for Windows "MSI installer - All Users"
https://awscli.amazonaws.com/AWSCLIV2.msi

### Direct Download for Windows "MSI installer - Current User Only"
https://awscli.amazonaws.com/AWSCLIV2-User.msi


# Python Requirements
```
uvicorn[standard]
boto3
fastapi
pydantic
```

# Environment Requirements
You need to fill out the .env [See link here](https://github.com/CyberSleuth-MS/CUI-Enclave-Dashboard-WIP/blob/main/.env) on your machine using your AWS SSO Login Profile NAME. It is required for the assess.py scanner
