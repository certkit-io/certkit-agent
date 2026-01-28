# escape=`
ARG BASE_IMAGE=mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019
FROM ${BASE_IMAGE}

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

WORKDIR C:\app

COPY scripts/install.ps1 C:\app\install.ps1
COPY dev/iis/start-services.ps1 C:\app\start-services.ps1

EXPOSE 80 443

ENTRYPOINT ["powershell.exe", "-File", "C:\\app\\start-services.ps1"]
