# escape=`
ARG BASE_IMAGE=mcr.microsoft.com/windows/servercore:ltsc2019
FROM ${BASE_IMAGE}

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

ARG APACHE_ZIP_URL=https://www.apachelounge.com/download/VS18/binaries/httpd-2.4.66-260107-Win64-VS18.zip
ENV APACHE_ZIP_URL=${APACHE_ZIP_URL}

# RUN [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `
#     iex ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')); `
#     choco install -y --no-progress vcredist140; `
#     choco install -y --no-progress openssl.light

ADD https://aka.ms/vs/18/release/VC_redist.x64.exe C:/installers/vcredist.exe
RUN C:\installers\vcredist.exe /quiet /install

ADD https://www.apachelounge.com/download/VS18/binaries/httpd-2.4.66-260107-Win64-VS18.zip c:\installers\apache.zip
RUN Expand-Archive -Path c:\installers\apache.zip -DestinationPath C:\; 


# ADD https://slproweb.com/download/Win64OpenSSL_Light-3_6_1.exe c:\installers\openssl.exe
# RUN c:\installers\openssl.exe /quiet /install



WORKDIR C:\app

COPY scripts/install.ps1 C:\app\install.ps1
COPY dev/apache-windows/start-services.ps1 C:\app\start-services.ps1

EXPOSE 443

ENTRYPOINT ["powershell.exe", "-File", "C:\\app\\start-services.ps1"]
