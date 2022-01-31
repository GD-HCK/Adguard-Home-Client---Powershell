# Readme

## AdGuard Home Powershell Client


## Getting Started Guide
* `Windows 10`

    Install docker via [Docker Hub](https://hub.docker.com/editions/community/docker-ce-desktop-windows/ "Docker Hub")
* `Windows Server`
    ```powershell
    # Run the below as administrator in Powershell 5.1 only for windows server
    install-module DockerProvider -Force 
    install-package Docker -ProviderName DockerProvider -Force
    ```

## Hard-limit resource access to WSL2
* #### Open/create the .wslconfig file
    ```powershell
    notepad "$env:USERPROFILE/.wslconfig"
    ```
* #### Amend the file with the below content and save it
    ```
    [wsl2]
    memory=3GB   # Limits VM memory in WSL 2 up to 3GB
    processors=4 # Makes the WSL 2 VM use two virtual processors
    ```
* #### Restart docker desktop service
    ```powershell
    # Run the below as administrator
    Restart-Service -Name com.docker.service -Force
    ```
* #### Restart wsl2
    ```powershell
    wsl --shutdown
    wsl
    ```

## Docker basic commands
* #### Start container in Detached mode (Background run):
    ```powershell
    # Syntax:
    docker run --detach --name $container_name --publish 8080:8080 `
               --env $required_environment_variable  "$image_name`:$tag"
    # Example:
    docker run -d --name ubuntu -p 8080:80 ubuntu:latest
    ``` 
* #### Start container in Interactive mode (Foreground run):
    ```powershell
    # Syntax:
    docker run --interactive --name $container_name --publish 8080:8080 `
               --env $required_environment_variable  "$image_name`:$tag"
    # Use Ctrl+P+Q to exit the foreground console and leave the container running in the background
    # Example:
    docker run -it --name ubuntu -p 8080:80 ubuntu:latest
    ```
* #### Remove all stopped containers and associated unused volumes
    ```powershell
    docker ps --filter "status=exited" -q | %{docker container rm -v $_} `
    && docker volume rm $(docker volume ls -f dangling=true -q)
    ```

## Docker Topics
`Check each folder's .md file for instructions`

1. [Automation](./Automation/README.md)
1. [Compose](./Compose/README.md) [In Progress]
1. [Octopus Container](./Octopus%20Container/README.md)
1. [Wordpress Container](./Wordpress%20Container/README.md)
