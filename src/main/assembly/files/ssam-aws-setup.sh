#!/bin/sh

cwd=`pwd`

cd /ds/PingDirectory/samples/
unzip -q ssam.zip
./ssam/setup.sh --serverRoot /ds/PingDirectory --ldapPort 1636 \
         --bindDN "cn=Directory Manager" --bindPassword password --useSSL \
         --trustStorePath /ds/PingDirectory/config/truststore \
         --peopleBaseDN ou=People,dc=example,dc=com \
         --smtpServerHostname smtp.example.com \
         --smtpSenderEmailAddress 'do-not-reply@example.com'

sed -i.bak s/\"address\":\".*ec2.internal\"/\"address\":\"localhost\"/ /ds/PingDirectory/webapps/ssam-config/ldap-connection-details.json
sed -i.bak s/\"verify-address-in-certificate\":true/\"verify-address-in-certificate\":false/ /ds/PingDirectory/webapps/ssam-config/ldap-connection-details.json

# Rebuild the mobile attribute index created by the ssam installation
../bin/rebuild-index --propertiesFilePath ../config/tools.properties --index mobile --baseDN dc=example,dc=com --task

cd $cwd
