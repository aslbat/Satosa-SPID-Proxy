# Satosa-SPID-Proxy
Guida per l'integrazione dell'autenticazione SPID tramite proxy SP<->IDPSAML2<->SPSpid<->IDPSpid con Satosa. La procedura comprende tutti i passi necessari per effettuare l'onboarding partendo da zero e da un OS linux Oracle Linux 9.0.

## Requisiti del sistema
Dal 1 Marzo 2021 le pubbliche amministrazioni devono supportare l'autenticazione via SPID.
In generale, il sistema deve permettere all'utente di scegliere se autenticarsi presso l'identity provider, IDP, istituzionale o su uno o più IDP esterni (il primo sistema di autenticazione esterno considerato è quello di SPID).
La soluzione permette di:

* utilizzare un IDP esterno per l'autenticazione dell'utente
* non modificare la configurazione del service provider SP che comunica solo con l'IDP istituzionale

Termini utilizzati nella guida:

* **IDP_SAML2**: IDP interno, utilizzabile da altre applicazioni standard SAML2
* **IDP_SPID**: IDP esterno (nel caso implementativo gli Identity Provider di SPID)
* **SP_SPID**: SP installato nello stesso server di IDP_SAML2 collegato a IDP_SPID

### Vantaggi rispetto a Shibboleth

* I metadata vengono creati in automatico da Satosa
* I metadata vengono firmati in automatico da Satosa
* Non è necessario installare:
  * Jetty
  * Apache
  * Mod_Shib (ShibbolethSP)
  * ShibbolethIDP
  * ShibbolethDS
* Non c'è passaggio di RemoteUser, Header HTTP e altro on-the-wire
* I software da installare con Satosa sono:
  * Nginx
  * Satosa

###  Il flusso
Il flusso di esecuzione può essere sintetizzato come segue:

1. l'utente si connette ad un servizio SP1
2. il servizio SP1 lo reinderizza a IDP_SAML2
3. IDP_SAML2 come SP_SPID mostra una pagina con il pulsante entra con SPID che consente di scegliere l'IDP SPID e si autentica
4. l'utente autenticato ritorna su SP1, con gli attributi richiesti

### Hostname utilizzati

Supponiamo che il nostro ente abbia il dominio DOMINIO_ENTE.it, consideriamo questi hostname

* Nome validator di test: **spidvalidator.DOMINIO_ENTE.it** (ip di esempio: **10.0.0.8**)
* Nome proxy SPID: **spidauth.DOMINIO_ENTE.it** (ip di esempio: **10.0.0.9**)
* Nome applicazione da configurare per accesso a spid: **servizio_al_pubblico.DOMINIO_ENTE.it** (ip di esempio: **10.0.0.10**)

### 1. Creazione servizio spid validator di test
1. Predisponiamo un server con Oracle Linux 9.0 e docker (ricordiamoci che docker va installato
tramite repository docker, non usando i pacchetti di redhat). Il server deve rispondere all'hostname:
`spidvalidator.DOMINIO_ENTE.it` e ha come ip: `10.0.0.8`.

2. Una volta installato disabilitiamo SELINUX, per non avere problemi con i container, inserendo `SELINUX=permissive` nel file `/etc/sysconfig/selinux`

3. Installiamo docker con questi comandi:

  ```bash
### COMPLETATA L'INSTALLAZIONE DI OL9 INSTALLIAMO DOCKER
dnf install -y yum-utils
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum install docker-ce docker-ce-cli containerd.io
```

4. Configuriamo la sincronizzazione dell'orario. Tutte i server coivolti devono avere l'orario sincronizzato
correttamente per evitare errori durante l'autenticazione:

  ```bash
#### SINCRONIZZAZIONE OROLOGIO - IMPORTANTE !! #######################################################
# Configurazione sincronizzazione orologio (da fare su tutti i server coinvolti)
dnf -y install chrony
systemctl enable chronyd
# Rimuovo dal file /etc/chrony.conf le righe con pool gia' presenti e aggiungo i server italiani:
sed -i 's/^pool.*//' /etc/chrony.conf
echo 'pool ntp1.inrim.it iburst' | tee -a /etc/chrony.conf
echo 'pool ntp2.inrim.it iburst' | tee -a /etc/chrony.conf
# Avvio il servizio
systemctl start chronyd
# Verificare lo stato con il comando: chronyc -n tracking
# il Leap status deve essere "Normal"
#### SINCRONIZZAZIONE OROLOGIO - IMPORTANTE !! #######################################################
```

5. Configuriamo gli hostname (nel caso siano configurati sul server DNS questa configurazione non è necessaria)

  Nel file /etc/hosts del server docker 10.0.0.8 inserire gli host coinvolti con questi comandi:

  ```bash
echo '10.0.0.8  spidvalidator.DOMINIO_ENTE.it' | tee -a /etc/hosts
echo '10.0.0.9  spidauth.DOMINIO_ENTE.it' | tee -a /etc/hosts
echo '10.0.0.10 servizio_al_pubblico.DOMINIO_ENTE.it' | tee -a /etc/hosts
```

6. Avviamo il container italia/spid-saml-check con questi comandi:

  ```bash
  ## Comando per eliminarlo: docker container stop spid_validator && docker container rm spid_validator
  docker run --name spid_validator -p 443:443 --env NODE_HTTPS_PORT=443 --add-host=spidvalidator.DOMINIO_ENTE.it:10.0.0.8 --add-host=spidauth.DOMINIO_ENTE.it:10.0.0.9 --add-host=servizio_al_pubblico.DOMINIO_ENTE.it:10.0.0.10 italia/spid-saml-check:1.9.2
```

7. Configuriamo il container per utilizzare la porta 443 invece che la 8443 e gli hostname scelti sopra:

  ```bash
# Entrare nel container e fare queste modifiche
docker exec -ti spid_validator /bin/bash
apt install nano iputils-ping vim -y
sed -i 's/localhost:8443/spidvalidator.DOMINIO_ENTE.it/' /spid-saml-check/spid-validator/config/idp.json
sed -i 's/localhost:8443/spidvalidator.DOMINIO_ENTE.it/' /spid-saml-check/spid-validator/config/idp_demo.json
sed -i 's/localhost/spidvalidator.DOMINIO_ENTE.it/'      /spid-saml-check/spid-validator/config/server.json
sed -i 's/8443/443/'                               /spid-saml-check/spid-validator/config/server.json
# Questo serve a non mettere :443 nel link https nei metadata.xml
sed -i 's/"useProxy": false/"useProxy": true/'     /spid-saml-check/spid-validator/config/server.json
exit
docker container stop spid_validator && docker container start spid_validator
```

8. Verifichiamo se l'installazione ha funzionato. Dovrebbero rispondere i seguenti link (le credenziali sono validator/validator):
* https://10.0.0.8/
* https://10.0.0.8/metadata.xml
* https://10.0.0.8/demo
* https://10.0.0.8/demo/metadata.xml

  e aggiungendo gli host al proprio PC, modificando come amministratore il file `C:\Windows\System32\drivers\etc\hosts` a questi link:

* https://spidvalidator.DOMINIO_ENTE.it/
* https://spidvalidator.DOMINIO_ENTE.it/metadata.xml
* https://spidvalidator.DOMINIO_ENTE.it/demo
* https://spidvalidator.DOMINIO_ENTE.it/demo/metadata.xml


### 2. Creazione certificato per firma metadata

Per la creazione della coppia di chiavi utilizzata per firmare il metadata.xml, utilizziamo
il container italia/spid-compliant-certificates. I file andranno configurati su satosa che
provvederà a firmare gli xml. Utilizziamo il docker installato sul server 10.0.0.8

1. Colleghiamoci al server 10.0.0.8 creamo la cartella /root/spid_certs dove il container
salverà i certificati:

  ```bash
# Correggo con chmod i permessi, altrimenti mi da accesso negato:
mkdir /root/spid_certs
chmod 777 -R /root/spid_certs
```

2. Eseguo il container col comando sotto, corregendo i parametri corretti:
  * DOMINIO_ENTE.it: inserire quello del proprio ente
  * org-id: deve essere uguale a PA:IT- seguito dal **codice ipa**, per esempio PA:IT-asl_bat
  * entity-id: deve essere uguale a entityID del tag EntityDescriptor nell'xml (quello generato da
    satosa è esattamente così: https://\<HOSTNAME_PROXY_SATOSA\>/spidSaml2/metadata)
  * validity: non c'è nessun requisito sulla validity, lo imposto 100 anni (36500 giorni) così non scade

  ```bash
docker run --name spid_genera_certificati -ti --rm \
    -v "/root/spid_certs:/certs" \
    italia/spid-compliant-certificates generator \
        --key-size 3072 \
        --common-name "DOMINIO_ENTE.it" \
        --days 36500 \
        --entity-id https://spidauth.DOMINIO_ENTE.it/spidSaml2/metadata \
        --locality-name Andria \
        --org-id "PA:IT-<CODICE_IPA>" \
        --org-name "ASL BT" \
        --sector public
```

  Una volta eseguito questo comando troverete nella cartella /root/spid_certs i file:
  * key.pem
  * csr.pem
  * crt.pem

  Salvarsi questi file scaricandoli dal server 10.0.0.8. I file si possono aprire su windows aggiungendo l'estensione .crt. Questi andranno copiati sul server proxy satosa.

### 3. Installazione e configurazione Satosa

1. A questo punto procediamo con l'installazione del server dove installeremo satosa e funzionerà da proxy SPID. Anche qui predisponiamo un nuovo server con Oracle Linux 9.0. Il server nell'esempio risponde all'hostname:
`spidauth.DOMINIO_ENTE.it` e ha come ip: `10.0.0.9`. L'installazione la faremo nella cartella `/opt/satosa_spid_proxy`.

2. Anche qui configuriamo la sincronizzazione dell'orario. Tutte i server coivolti devono avere l'orario sincronizzato correttamente per evitare errori durante l'autenticazione:

  ```bash
#### SINCRONIZZAZIONE OROLOGIO - IMPORTANTE !! #######################################################
# Configurazione sincronizzazione orologio (da fare su tutti i server coinvolti)
dnf -y install chrony
systemctl enable chronyd
# Rimuovo dal file /etc/chrony.conf le righe con pool gia' presenti e aggiungo i server italiani:
sed -i 's/^pool.*//' /etc/chrony.conf
echo 'pool ntp1.inrim.it iburst' | tee -a /etc/chrony.conf
echo 'pool ntp2.inrim.it iburst' | tee -a /etc/chrony.conf
# Avvio il servizio
systemctl start chronyd
# Verificare lo stato con il comando: chronyc -n tracking
# il Leap status deve essere "Normal"
#### SINCRONIZZAZIONE OROLOGIO - IMPORTANTE !! #######################################################
```

3. Installiamo i pacchetti che ci serviranno:

  ```bash
dnf install -y nginx chrony libffi-devel gcc git-core openssl-devel python3-devel python3-pip xmlsec1 procps pcre pcre-devel openssh-clients
```

4. Installiamo pip e virtualenv:

  ```bash
pip install -U pip
pip install -U virtualenv
```

5. Creamo la cartella dove installeremo satosa (scelgo `/opt/satosa_spid_proxy`) e la cartella dove andremo a
salvare i certificati generati dal container spid-compliant-certificates e che si trovano sul server 10.0.0.8
nella cartella /root/spid_certs:

  ```bash
mkdir -p /opt/satosa_spid_proxy/pki_spid
```

6. Copiamo i certificati creati con docker dal server 10.0.0.8 in `/root/spid_certs` al server satosa 10.0.0.9
in `/opt/satosa_spid_proxy/pki_spid`, con scp, o trasferendo i file da windows con WinSCP:
  ```bash
scp root@10.0.0.8:/root/spid_certs/* /opt/satosa_spid_proxy/pki_spid
```

7. Spostiamoci nella cartella `/opt/satosa_spid_proxy` e installiamo satosa:

  ```bash
cd /opt/satosa_spid_proxy
virtualenv -ppython3 satosa.env
source satosa.env/bin/activate
pip install --upgrade pip
git clone https://github.com/italia/Satosa-Saml2Spid.git repository
pip install -r repository/requirements.txt
# Copio i file di configurazione di esempio che andranno modificati
cp -R repository/example/* .
```

8. Disabilitiamo i plugin che non ci servono. Nel file `/opt/satosa_spid_proxy/proxy_conf.yaml`

  ```yaml
# commentare in FRONTEND_MODULES:
  # - "plugins/frontends/oidc_op_frontend.yaml"
#
# e in BACKEND_MODULES:
  # - "plugins/backends/saml2_backend.yaml"
```

9. Disabilitiamo il firewall sulle porte 80 e 443

  ```bash
firewall-cmd --zone=public --add-service=http
firewall-cmd --zone=public --add-service=https
firewall-cmd --zone=public --permanent --add-service=http
firewall-cmd --zone=public --permanent --add-service=https
```

10. Configuriamo gli host, se non gestiti dal DNS:
  ```bash
echo '10.0.0.9 spidauth.DOMINIO_ENTE.it' | tee -a /etc/hosts
echo '10.0.0.8  spidvalidator.DOMINIO_ENTE.it' | tee -a /etc/hosts
echo '10.0.0.10 servizio_al_pubblico.DOMINIO_ENTE.it' | tee -a /etc/hosts
```

11. Configuriamo nginx

  ```bash
# Facciamo una copia di backup della configurazione originale
mv /etc/nginx/nginx.conf /etc/nginx/nginx_bckol9.conf
```

  Creamo la cartella dove salveremo i certificati ssl registrati dal proprio ente:
  ```bash
mkdir /opt/nginx_certs
```

**Copiamo i certificati ssl registrati per il proprio ente per \*.DOMINIO_ENTE.it oppure se non wildcard
per spidauth.DOMINIO_ENTE.it, o utilizzare dei certificati self-signed, ma per il collaudo spid è necessario 
che i certificati siano validi**

  Creamo il file `/etc/nginx/nginx.conf` con questo contenuto:

  ```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;
# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 4096;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    include /etc/nginx/conf.d/*.conf;
}
```

  Creamo il file `/etc/nginx/conf.d/satosa.conf` con questo contenuto, cambiando DOMINIO_ENTE col proprio
  e verificando il percorso dei file del certificato ssl `_.DOMINIO_ENTE.it.cer` e `.key`:

```nginx
# the upstream component nginx needs to connect to
upstream satosa-saml2 {
  server unix:///opt/satosa_spid_proxy/tmp/sockets/satosa.sock;
}

# configuration of the server
server {
  listen      80;
  server_name spidauth.DOMINIO_ENTE.it;
  access_log /var/log/nginx/proxy_satosa_it.access.log;
  error_log  /var/log/nginx/proxy_satosa_it.error.log error;
  return 301 https://$host$request_uri;
}

server {
  server_name spidauth.DOMINIO_ENTE.it;
  listen 443 ssl;
  
  #####
  ##### QUI VANNO MESSE LE CHIAVI SSL REGISTRATE PER IL PROPRIO ENTE
  #####
  ssl_certificate /opt/nginx_certs/_.DOMINIO_ENTE.it.cer;
  ssl_certificate_key /opt/nginx_certs/_.DOMINIO_ENTE.it.key;

  access_log /var/log/nginx/proxy_satosa_it.log;
  error_log  /var/log/nginx/proxy_satosa_it.log error;

  # max upload size
  client_max_body_size 8M;
    
  # very long url for delega ticket
  large_client_header_buffers 4 16k;

  # SSL HARDENING
  # disable poodle attack
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  # COMMENTATO ssl_dhparam /etc/nginx/dhparam.pem;
  ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
  ssl_session_timeout  10m;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off; # Requires nginx >= 1.5.9
  ssl_stapling on; # Requires nginx >= 1.3.7
  ssl_stapling_verify on; # Requires nginx => 1.3.7
  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
  add_header X-Frame-Options DENY;
  add_header X-Content-Type-Options nosniff;
  add_header X-XSS-Protection "1; mode=block";
  add_header X-Robots-Tag none;
  # FINE SSL HARDENING

  # satosa static
  location /static  {
    alias /opt/satosa_spid_proxy/static;
    autoindex off;
  }

  # Finally, send all non-media requests to satosa server.
  location / {
    uwsgi_pass  satosa-saml2;
    uwsgi_param HTTP_X_FORWARDED_PROTOCOL https;

    # fix: Cookie SameSite: https://github.com/IdentityPython/SATOSA/issues/245
    proxy_cookie_path ~(/*) "$1; SameSite=None; Secure";

    # Enable HTTP Strict Transport Security with a 2 year duration
    add_header Strict-Transport-Security "max-age=63072000; ";
        
    # deny iFrame
    add_header X-Frame-Options "DENY";

    uwsgi_read_timeout 40;
    include     /opt/satosa_spid_proxy/uwsgi_setup/uwsgi_params;
    # fix long url upstream buffer size
    uwsgi_buffer_size          128k;
    uwsgi_buffers              4 256k;
    uwsgi_busy_buffers_size    256k;
  }
}
```

12. Configuriamo il servizio satosa:

  Creare il file `/etc/systemd/system/satosa.service` con questo contenuto:

  ```ini
Description=UWSGI server for Satosa Proxy
After=syslog.target
Requires=satosa.socket

[Service]
Type=simple
User=satosa
Group=satosa
WorkingDirectory=/opt/satosa_spid_proxy
ExecStart=/bin/bash -c 'cd /opt/satosa_spid_proxy && source satosa.env/bin/activate && uwsgi --ini ./uwsgi_setup/uwsgi/uwsgi.ini.socket --thunder-lock'
Restart=always
KillSignal=SIGQUIT

[Install]
WantedBy=sockets.target
```

  Creare il file `/etc/systemd/system/satosa.socket` con questo contenuto:

  ```ini
[Unit]
Description=Socket for satosa

[Socket]
SocketUser=satosa
SocketGroup=satosa
ListenStream=/opt/satosa_spid_proxy/tmp/sockets/satosa.sock
SocketMode=0770

[Install]
WantedBy=sockets.target
```

  Determiniamo la versione di python utilizzata con questo comando:

  ```bash
  python -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")'
```

  Sovrascriviamo il file `/opt/satosa_spid_proxy/uwsgi_setup/uwsgi/uwsgi.ini.socket` con questo contenuto
  sostituendo la stringa `python3.9` all'interno della proprietà `satosa_app` con la stringa recuperata al passo
  precedente:
  
  ```ini
[uwsgi]
# Questo deve essere il nome della cartella dove abbiamo installato satosa
project     = satosa_spid_proxy
base        = /opt

##################
################## INDIVIDUARE LA VERSIONE DI PYTHON DA INSERIRE NEL PERCORSO
##################
## SATOSA_APP=$VIRTUAL_ENV/lib/$(python -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')/site-packages/satosa
## uwsgi --wsgi-file $SATOSA_APP/wsgi.py  --socket /opt/satosa_spid_proxy/tmp/sockets/satosa.sock --callable app -b 32768
# Sostituire python3.9 con la versione di python installata. Per determinare la versione installata
# utilizzare questo comando: 
#    python -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")'
# l'output va messo al posto di python3.9 qui sotto
satosa_app  = /opt/satosa_spid_proxy/satosa.env/lib/python3.9/site-packages/satosa 

chdir       = %(base)/%(project)
uid         = satosa
gid         = satosa
socket      = %(base)/%(project)/tmp/sockets/satosa.sock
chmod-socket = 770

wsgi-file = %(satosa_app)/wsgi.py

callable = app

virtualenv  =  %(base)/%(project)/satosa.env

logto = %(base)/%(project)/logs/uwsgi/%(project).log
log-maxsize = 100000000
log-backupname = %(base)/%(project)/logs/uwsgi/%(project).old.log

# avoid: invalid request block size: 4420 (max 4096)...skip
buffer-size=32768

pidfile     = %(base)/%(project)/logs/uwsgi/%(project).pid
touch-reload    = %(base)/%(project)/proxy_conf.yaml
```

  Sovrascriviamo i seguenti file con quelli presenti in questa cartella nel repository:
  
  * `/opt/satosa_spid_proxy/proxy_conf.yaml`
  * `/opt/satosa_spid_proxy/plugins/backends/spidsaml2_backend.yaml`
  * `/opt/satosa_spid_proxy/plugins/frontends/saml2_frontend.yaml`
  * `/opt/satosa_spid_proxy/plugins/microservices/target_based_routing.yaml`

  Aggiornando:
  * per tutti i file DOMINIO_ENTE.it con il proprio dominio
  * in `proxy_conf.yaml` sostituire i CHANGE_ME con stringhe casuali
  * in `saml2_frontend.yaml` correggere i contatti in `contact_type`
  * in `spidsaml2_backend.yaml`:
    * correggere name e display name di organization
    * in contact_person -> contact_type aggiornare con i propri valori
      * telephone_number: numero di telefono col +39 avanti
      * email_address: indirizzo posta elettronica non personale (per esempio: sistemi.informativi@DOMINIO_ENTE.it)
      * VATNumber: partita iva ente
      * IPACode: codice ipa ente

  Creamo le cartelle e abilitiamo i servizi all'avvio, ricordiamoci che il servizio `satosa` viene eseguito come utente `satosa`
  per cui il proprietario della cartella `/opt/satosa_spid_proxy` deve essere l'utente `satosa`, quindi anche se abbiamo
  modificato i file come root, il `chown` sotto ripristina i permessi della `/opt/satosa_spid_proxy` in modo tale che
  il proprietario sia l'utente `satosa`:
  
  ```bash
mkdir -p /opt/satosa_spid_proxy/tmp/sockets
mkdir -p /opt/satosa_spid_proxy/logs/uwsgi
useradd satosa
systemctl daemon-reload
systemctl enable satosa.sock
systemctl enable satosa.service
systemctl enable nginx
chown -R satosa:satosa /opt/satosa_spid_proxy
usermod -a -G satosa nginx
service nginx restart
service satosa restart
```

13. Verifichiamo se l'installazione ha funzionato. Dovrebbero rispondere i seguenti link:
  * https://10.0.0.9/Saml2IDP/metadata
  * https://10.0.0.9/spidSaml2/metadata

  e aggiungendo gli host al proprio PC, modificando come amministratore il file `C:\Windows\System32\drivers\etc\hosts` a questi link:
  
  * https://spidauth.DOMINIO_ENTE.it/Saml2IDP/metadata
  * https://spidauth.DOMINIO_ENTE.it/spidSaml2/metadata
  
14. Aggiungiamo i metadata degli IDP ufficiali e di quello di test. Con questo comando aggiungiamo quelli ufficiali:
  ```bash
wget https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml -O /opt/satosa_spid_proxy/metadata/idp/spid-entities-idps.xml
```

  Poi aggiungiamo quelli di test, andiamo su questi link e scarichiamoci i file xml:

  * https://spidvalidator.DOMINIO_ENTE.it/metadata.xml
  * https://spidvalidator.DOMINIO_ENTE.it/demo/metadata.xml

  Apriamo questi file xml e copiamoci per ognuno tutto il tag `<md:EntityDescriptor`. Una volta copiati li inseriamo
  nel file `/opt/satosa_spid_proxy/metadata/idp/spid-entities-idps.xml` alla fine prima della chiusura del tag
  finale `</md:EntitiesDescriptor>`, in questo modo:

  ```xml
    ...
    <md:EntityDescriptor ID="_feb2b3550c8b9605fd73fe0fe8d3c94f4ba8f5e74e" entityID="https://spidvalidator.DOMINIO_ENTE.it" ....
    <md:EntityDescriptor ID="_3f7b3aa70ad110567535fa94636428f5f1f656ecf0" entityID="https://spidvalidator.DOMINIO_ENTE.it/demo" ...
</md:EntitiesDescriptor>
```

15. Aggiungiamo il validator di test come IDP all'interno del file js che ci va a costruire il pulsante entra con spid.
  Modifichiamo il file `/opt/satosa_spid_proxy/static/spid/spid-idps.js` aggiungendo gli IDP di test:

  ```javascript
# aggiungendo i provider di test:
const idps = [
  // aggiunti i 2 provider di test:
  {"entityName": "SPID Test", "entityID": "https://spidvalidator.DOMINIO_ENTE.it", "logo": ""},
  {"entityName": "SPID Test DEMO", "entityID": "https://spidvalidator.DOMINIO_ENTE.it/demo", "logo": ""},

  // idp ufficiali:
  {"entityName": "Aruba ID", "entityID": "https://loginspid.aruba.it", "logo": "spid/spid-idp-arubaid.svg"},
  .....
  {"entityName": "Tim ID", "entityID": "https://login.id.tim.it/affwebservices/public/saml2sso", "logo": "spid/spid-idp-timid.svg"}
]
```

16. A questo punto la configurazione è completa. I SP interni che utilizzeranno il proxy andranno configurati in satosa
salvando i loro metadata.xml come service provider nella cartella `/opt/satosa_spid_proxy/metadata/sp`


### 4. Configurazione servizio di test

Anche qui installiamo un'applicazione di test in php. Utilizziamo sempre Oracle Linux 9,
impostiamo l'ip del nostro esempio 10.0.0.10 e hostname servizio_al_pubblico.DOMINIO_ENTE.it.
Configuriamo come sopra la **sincronizzazione dell'orologio** con chrony e il file `/etc/hosts` sempre
con gli host configurati nei server precedenti.

1. Installiamo i pacchetti che ci servono:

```bash
dnf install -y nginx php php-xml php-fpm
systemctl enable --now php-fpm
cd /var
wget https://github.com/simplesamlphp/simplesamlphp/releases/download/v1.19.6/simplesamlphp-1.19.6.tar.gz
tar xzf simplesamlphp-1.19.6.tar.gz
mv simplesamlphp-1.19.6 simplesamlphp
\rm simplesamlphp-1.19.6.tar.gz
```

2. Configuriamo il virtualhost in nginx, creamo il file `/etc/nginx/conf.d/servizio_al_pubblico.conf` con questo contenuto:

```nginx
##############################################################
# In /etc/nginx/conf.d/servizio_al_pubblico.conf
#
# Virtual Host servizio_al_pubblico.DOMINIO_ENTE.it
##############################################################
server {
    listen 443 ssl;
    server_name servizio_al_pubblico.DOMINIO_ENTE.it;
    ssl_certificate /opt/nginx_certs/_.DOMINIO_ENTE.it.cer;
    ssl_certificate_key /opt/nginx_certs/_.DOMINIO_ENTE.it.key;
    ssl_protocols          TLSv1.3 TLSv1.2;
    ssl_ciphers            EECDH+AESGCM:EDH+AESGCM;

    location ^~ /simplesaml {
        alias /var/simplesamlphp/www;
        index index.php;

        location ~ ^(?<prefix>/simplesaml)(?<phpfile>.+?\.php)(?<pathinfo>/.*)?$ {
            include          fastcgi_params;
            fastcgi_pass     php-fpm;
            fastcgi_param SCRIPT_FILENAME $document_root$phpfile;

            # Must be prepended with the baseurlpath
            fastcgi_param SCRIPT_NAME /simplesaml$phpfile;

            fastcgi_param PATH_INFO $pathinfo if_not_empty;
        }
    }
}
##############################################################
```

3. Scarico l'xml dell'IDP interno satosa:

```bash
wget --no-check-certificate https://spidauth.DOMINIO_ENTE.it/Saml2IDP/metadata -O /var/simplesamlphp/config/metadata-idp-satosa.xml
```

4. Modifico la configurazione di simplesamlphp, impostando i parametri nel file `/var/simplesamlphp/config/config.php`:

```php
    'secretsalt' => 'defaultsecret____stringa___casuale',
    'auth.adminpassword' => 'password123_utente_admin',
    'timezone' => 'Europe/Rome',
    # il logger (altrimenti va sul syslog)
    'logging.handler' => 'file',
    'metadata.sources' => [
        ['type' => 'flatfile'],
        ['type' => 'xml', 'file' => 'config/metadata-idp-satosa.xml']
    ],
```

6. Configuro i permessi e riavvio nginx:

```bash
# Altrimenti i log non riesce a scriverli nella cartella log (vedi /var/log/php-fpm/www-error.log)
chown -R apache:apache /var/simplesamlphp
service nginx restart
```

7. Accedere a questo link e verificare che funzioni:
https://servizio_al_pubblico.DOMINIO_ENTE.it/simplesaml/module.php/core/frontpage_welcome.php

8. Scarico l'xml del sp di simplesaml andando da Federazione > Mostra metadati e lo salvo nella
cartella metadata/sp sul server satosa configurato prima con ip 10.0.0.8

9. A questo punto provo l'autenticazione, accedere a questo link:
https://servizio_al_pubblico.DOMINIO_ENTE.it/simplesaml/module.php/core/frontpage_welcome.php
andare in Autenticazione > Prova le fonti di autenticazione configurate > default-sp
Scegliere il provider VALIDATOR DEMO o VALIDATOR e inserire per il DEMO le utenze di test visibili
da: https://spidvalidator.aslbat.it/demo > visualizza utenti di test, per il VALIDATOR
l'utente validator/validator.
Ricordarsi prima però di caricare l'xml del service provider di satosa con questo link: https://10.0.0.9/spidSaml2/metadata
nella sezione Metadata SP > Download del validator a questo link  https://spidvalidator.aslbat.it

10. Per non passare dalla schermata di scelta dell'IDP, tanto c'è solo 1 configurato
impostare la proprieta' idp nel file /var/simplesamlphp/config/authsources.php
in questo modo, invece di null:

```php
    'default-sp' => [
        'saml:SP',

        //'idp' => null,
        'idp' => 'https://spidauth.DOMINIO_ENTE.it/Saml2IDP/metadata',
        ....
```



