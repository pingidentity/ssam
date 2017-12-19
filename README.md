# Ping Identity Self-Service Account Manager

## Introduction

The Ping Identity Self-Service Account Manager (SSAM) is a Java web application
that enables users to perform their own account registration, profile updates,
and password changes.  The SSAM application works with account data and user
profiles which are stored in the Ping Identity Directory Server.

SSAM can be customized for branding, look and feel, and can be used as the
starting point for extensions and custom application development.

SSAM can provide its own user authentication (login) service, but can also be
deployed with authentication delegated to a PingFederate server.


## Installation and Configuration

Refer to the PDF documentation included with this software package for
installation, configuration, integration, and customization information.

### Basic Setup

After unpacking the SSAM code it can be setup using the following command:
```shell
./ssam/setup.sh --serverRoot /ds/PingDirectory --ldapPort 1636 \
         --bindDN "cn=Directory Manager" --bindPassword password --useSSL \
         --trustStorePath /ds/PingDirectory/config/truststore \
         --peopleBaseDN ou=People,dc=example,dc=com \
         --smtpServerHostname smtp.example.com \
         --smtpSenderEmailAddress 'do-not-reply@example.com'
```


### Support and reporting bugs

This is unsupported sample code. Help will be provided on a best-effort basis through GitHub. Please report issues
using the project's [issue tracker](https://github.com/pingidentity/ssam/issues).


## License

This is licensed under the Apache License 2.0.