# escape=`
ARG BASE_IMAGE=mcr.microsoft.com/windows/servercore:ltsc2019
FROM ${BASE_IMAGE}

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

RUN New-Item -ItemType Directory -Force -Path C:\installers | Out-Null

COPY dev/apache-windows/vendor/vcredist.x64.exe C:\installers\vcredist.exe
RUN C:\installers\vcredist.exe /quiet /install

COPY dev/apache-windows/vendor/apache.zip C:\installers\apache.zip
RUN Expand-Archive -Path C:\installers\apache.zip -DestinationPath C:\; 

WORKDIR C:\app

COPY scripts/install.ps1 C:\app\install.ps1
COPY dev/apache-windows/start-services.ps1 C:\app\start-services.ps1

EXPOSE 443

ENTRYPOINT ["powershell.exe", "-File", "C:\\app\\start-services.ps1"]
