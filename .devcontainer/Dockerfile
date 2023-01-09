# [Choice] Alpine version: 3.16, 3.15, 3.14, 3.13 or leave blank for latest
FROM mcr.microsoft.com/vscode/devcontainers/base:0-alpine

# ** [Optional] Uncomment this section to install additional packages. **
# RUN apk update \
#     && apk add --no-cache <your-package-list-here>
ENV TZ=Europe/Berlin
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=DontWarn
ENV DEBIAN_FRONTEND noninteractive
ENV CONFIGURATION_DIR_PATH supporting_files/configuration
ENV SCRIPTS_DIR_PATH supporting_files/scripts

ARG USERNAME=vscode
ARG USERHOME=/home/${USERNAME}

RUN apk add --no-cache shadow

# fixes vcs_info: function definition file not found For Oh-my-zsh
RUN apk add zsh-vcs

# REFRESHED_AT YYYY-MM-DD
ENV REFRESHED_AT 2022-01-06 

# # Install dependencies
RUN apk update && \ 
    apk add postfix wget sudo git pwgen zip unzip curl go

# Add image configuration and scripts
ADD ${SCRIPTS_DIR_PATH}/post-create.sh /post-create.sh
RUN chmod 755 /post-create.sh

# Time Zone
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# configuration for zsh and commitizen
COPY ${CONFIGURATION_DIR_PATH}/.zshrc ${USERHOME}/.zshrc
COPY ${CONFIGURATION_DIR_PATH}/.czrc ${USERHOME}/.czrc
RUN chown vscode:vscode ${USERHOME}/.zshrc ${USERHOME}/.czrc \
    && chmod +x ${USERHOME}/.zshrc ${USERHOME}/.czrc

WORKDIR /usr/share/rtldev-middleware-dnscontrol
ENTRYPOINT exec top -b