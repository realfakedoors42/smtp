#!/bin/bash

#Conf Vars
HNAME="<DOMAIN NAME>"
HNAMEH="<DOMAIN NAME>"

FROM_NAME='noreply'

#Sys Vars
ADDR=`hostname -I`

#Hostname
hostnamectl set-hostname $HNAME

chk1=`grep -F $HNAME /etc/hosts | wc -m`
if (($chk1 > 0))
    then
        echo "Hostname already exists"
        #exit 0
fi

echo "127.0.1.1 $HNAME $HNAMEH" >> /etc/hosts
echo "127.0.0.1 $HNAME" >> /etc/hosts

echo 'Checking PTR record'
RES=`dig -x $ADDR +short | wc -m`

if(($RES > 0))
    then
        echo "- PTR record not found."
        #exit 0
fi

adduser --disabled-password --gecos "" $FROM_NAME

ufw allow smtp

echo "Installing postfix,dovecot & opendkim"
apt-get update
apt-get install mailutils -y
apt-get install postfix postfix-policyd-spf-python -y
apt-get install dovecot-core dovecot-imapd dovecot-lmtpd -y
apt-get install opendkim opendkim-tools -y
apt autoremove

line=1
hostLine=-1
destinationLine=-1

while IFS="" read -r p || [ -n "$p" ]
do
    if [[ $p  == *"myhostname ="* ]]; then
            ((hostLine=line))
    fi
    
    if [[ $p  == *"mydestination ="* ]]; then
            ((destinationLine=line))
    fi
    
    ((line++))
done < /etc/postfix/main.cf

hostR="myhostname = mail.$HNAME"

if (( $hostLine == -1 ))
    then
        echo $hostR >> /etc/postfix/main.cf
    else
        sed -i.bak "${hostLine}s|^.*$|$hostR|" /etc/postfix/main.cf
fi

distR="mydestination = \$myhostname, \$mydomain, localhost.localdomain, , localhost"

if (( $destinationLine == -1 ))
    then
        echo $distR >> /etc/postfix/main.cf
    else
        sed -i.bak "${destinationLine}s|^.*$|$distR|" /etc/postfix/main.cf
fi

echo "mydomain = $HNAME" >> /etc/postfix/main.cf

extra=$(cat <<-END
mailbox_transport = lmtp:unix:private/dovecot-lmtp
smtputf8_enable = no
policyd-spf_time_limit = 3600
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    check_policy_service unix:private/policyd-spf      
# Milter configuration
milter_default_action = accept
milter_protocol = 6
smtpd_milters = local:/opendkim/opendkim.sock
non_smtpd_milters = \$smtpd_milters
END
)

echo "$(printf "$extra")" >> /etc/postfix/main.cf

echo "Restarting postifx.."
systemctl restart postfix

echo "root:           $FROM_NAME" >> /etc/aliases
newaliases

ufw allow 587/tcp
ufw allow 465/tcp
ufw allow 143/tcp
ufw allow 993/tcp

echo "Installing certbot"
apt install software-properties-common -y
add-apt-repository ppa:certbot/certbot
apt update
apt install certbot python3-certbot-nginx -y


echo "Creating virtual host"

mkdir /var/www/mail > /dev/null 2>&1
touch /etc/nginx/sites-available/mail > /dev/null 2>&1
ln -s /etc/nginx/sites-available/mail /etc/nginx/sites-enabled/mail > /dev/null 2>&1

code=$(cat <<-END
server {
      listen 80;
      server_name mail.$HNAME;

      root /var/www/mail;

      location ~ /.well-known/acme-challenge {
         allow all;
      }
}
END
)

truncate -s 0 /etc/nginx/sites-enabled/mail
echo "$(printf "$code")" >> /etc/nginx/sites-enabled/mail
mkdir /var/www/mail > /dev/null 2>&1
chown www-data:www-data /var/www/mail -R 

nginx -t
service nginx configtest

certbot --nginx --agree-tos --redirect --hsts --staple-ocsp -d mail.$HNAME --non-interactive --email $FROM_NAME@$HNAME

start=0
end=0
line=1

while IFS="" read -r p || [ -n "$p" ]
do
    if [[ $p  == *"#tlsproxy  unix"* ]]; then
            ((start=line))
    fi
    
    if [[ $p  == *"#smtps     inet"* ]]; then
            ((end=line))
    fi
    
    ((line++))
done < /etc/postfix/master.cf

echo "Configuring POSTFIX"

masterD=$(cat <<-END
#tlsproxy  unix  -       -       y       -       0       tlsproxy
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
#  -o smtpd_tls_auth_only=yes
#  -o smtpd_reject_unlisted_recipient=no
#  -o smtpd_client_restrictions=\$mua_client_restrictions
#  -o smtpd_helo_restrictions=\$mua_helo_restrictions
#  -o smtpd_sender_restrictions=\$mua_sender_restrictions
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
#  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_tls_wrappermode=no
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
#smtps     inet  n       -       y       -       -       smtpd
END
)

sed -i.bak "${start},${end}d" /etc/postfix/master.cf
POWA=`perl -slpe 'print $s if $. == $n' -- -n=$start -s="$masterD" /etc/postfix/master.cf`
truncate -s 0 /etc/postfix/master.cf
echo "$(printf "$POWA")" >> /etc/postfix/master.cf

ADD='policyd-spf  unix  -       n       n       -       0       spawn
    user=policyd-spf argv=/usr/bin/policyd-spf'
echo "$(printf "$ADD")" >> /etc/postfix/master.cf


start=0
end=0
line=1

while IFS="" read -r p || [ -n "$p" ]
do
    if [[ $p  == *"# TLS parameters"* ]]; then
            ((start=line))
    fi
    
    if [[ $p  == *"# See /usr/share/doc/postfix/TLS_README.gz in the postfix-doc package for"* ]]; then
            ((end=line-1))
    fi
    
    ((line++))
done < /etc/postfix/main.cf


data=$(cat <<-END
# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/example.com/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/example.com/privkey.pem

smtpd_use_tls=yes
smtpd_tls_security_level = encrypt
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1
smtpd_tls_loglevel = 1
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache

smtp_use_tls=yes
smtp_tls_security_level = may
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1
smtp_tls_loglevel = 1
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
END
)


sed -i.bak "${start},${end}d" /etc/postfix/main.cf
POWA=`perl -slpe 'print $s if $. == $n' -- -n=$start -s="$data" /etc/postfix/main.cf`
truncate -s 0 /etc/postfix/main.cf
echo "$(printf "$POWA")" >> /etc/postfix/main.cf

service postfix restart

echo "Configuring Dovecot (Auth)"

echo "protocols = imap lmtp" >> /etc/dovecot/dovecot.conf
adduser dovecot mail

echo "disable_plaintext_auth = yes" >> /etc/dovecot/conf.d/10-auth.conf
echo "auth_username_format = %n" >> /etc/dovecot/conf.d/10-auth.conf

sed -i.bak 's/^auth_mechanisms =.*/auth_mechanisms = plain login/' /etc/dovecot/conf.d/10-auth.conf

echo "Configuring Dovecot (SSL)"

sed -i.bak "s@^ssl_cert = .*@ssl_cert = </etc/letsencrypt/live/$HNAME/fullchain.pem@" /etc/dovecot/conf.d/10-ssl.conf
sed -i.bak "s@^ssl_key = .*@ssl_key = </etc/letsencrypt/live/$HNAME/privkey.pem@" /etc/dovecot/conf.d/10-ssl.conf




start=0
end=0
line=1

while IFS="" read -r p || [ -n "$p" ]
do
    if [[ $p  == *"service lmtp {"* ]]; then
            ((start=line))
    fi
    
    if [[ $p  == *"service imap {"* ]]; then
            ((end=line-2))
    fi
    
    ((line++))
done < /etc/dovecot/conf.d/10-master.conf

data=$(cat <<-END
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
END
)

sed -i.bak "${start},${end}d" /etc/dovecot/conf.d/10-master.conf
POWA=`perl -slpe 'print $s if $. == $n' -- -n=$start -s="$data" /etc/dovecot/conf.d/10-master.conf`
truncate -s 0 /etc/dovecot/conf.d/10-master.conf
echo "$(printf "$POWA")" >> /etc/dovecot/conf.d/10-master.conf

start=0
end=0
line=1

while IFS="" read -r p || [ -n "$p" ]
do
    if [[ $p  == *"service auth {"* ]]; then
            ((start=line))
    fi
    
    if [[ $p  == *"service auth-worker {"* ]]; then
            ((end=line-2))
    fi
    
    ((line++))
done < /etc/dovecot/conf.d/10-master.conf

data=$(cat <<-END
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
END
)

sed -i.bak "${start},${end}d" /etc/dovecot/conf.d/10-master.conf
POWA=`perl -slpe 'print $s if $. == $n' -- -n=$start -s="$data" /etc/dovecot/conf.d/10-master.conf`
truncate -s 0 /etc/dovecot/conf.d/10-master.conf
echo "$(printf "$POWA")" >> /etc/dovecot/conf.d/10-master.conf

echo "SPF and DKIM"

gpasswd -a postfix opendkim

line=0
start=0
end=0

while IFS="" read -r p || [ -n "$p" ]
do
    if [[ $p  == *"# Commonly-used options"* ]]; then
            ((start=line))
    fi
    
    if [[ $p  == *"# Socket smtp://localhost"* ]]; then
            ((end=line-2))
    fi
    
    ((line++))
done < /etc/opendkim.conf

data=$(cat <<-END
# Commonly-used options; the commented-out versions show the defaults.
Canonicalization        simple
Mode                    sv
SubDomains              no

AutoRestart         yes
AutoRestartRate     10/1M
Background          yes
DNSTimeout          5
SignatureAlgorithm  rsa-sha256
END
)

sed -i.bak "${start},${end}d" /etc/opendkim.conf
POWA=`perl -slpe 'print $s if $. == $n' -- -n=$start -s="$data" /etc/opendkim.conf`
truncate -s 0 /etc/opendkim.conf
echo "$(printf "$POWA")" >> /etc/opendkim.conf

data=$(cat <<-END
# Map domains in From addresses to keys used to sign messages
KeyTable           refile:/etc/opendkim/key.table
SigningTable       refile:/etc/opendkim/signing.table

# Hosts to ignore when verifying signatures
ExternalIgnoreList  /etc/opendkim/trusted.hosts

# A set of internal hosts whose mail should be signed
InternalHosts       /etc/opendkim/trusted.hosts
END
)

echo "$(printf "$data")" >> /etc/opendkim.conf

mkdir /etc/opendkim
mkdir /etc/opendkim/keys
chown -R opendkim:opendkim /etc/opendkim
chmod go-rw /etc/opendkim/keys

echo "*@$HNAME   default._domainkey.$HNAME" >> /etc/opendkim/signing.table
echo "default._domainkey.$HNAME  $HNAME:default:/etc/opendkim/keys/$HNAME/default.private" >> /etc/opendkim/key.table

echo "127.0.0.1" >> /etc/opendkim/trusted.hosts
echo "localhost" >> /etc/opendkim/trusted.hosts
echo "*.$HNAME"  >> /etc/opendkim/trusted.hosts

mkdir "/etc/opendkim/keys/$HNAME"
sudo opendkim-genkey -b 2048 -d "$HNAME" -D "/etc/opendkim/keys/$HNAME" -s default -v
chown opendkim:opendkim "/etc/opendkim/keys/$HNAME/default.private"

mkdir /var/spool/postfix/opendkim
chown opendkim:postfix /var/spool/postfix/opendkim



sed -i.bak "s@^Socket    local:/var/run/opendkim/opendkim.sock*@Socket                  Socket    local:/var/spool/postfix/opendkim/opendkim.sock@" /etc/opendkim.conf

systemctl restart opendkim postfix dovecot

echo "DONE!"
