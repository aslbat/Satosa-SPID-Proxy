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

        ### COMPLETATA L'INSTALLAZIONE DI OL9 INSTALLIAMO DOCKER
        dnf install -y yum-utils
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        yum install docker-ce docker-ce-cli containerd.io

4. Configuriamo la sincronizzazione dell'orario. Tutte i server coivolti devono avere l'orario sincronizzato
correttamente per evitare errori durante l'autenticazione:

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

5. Configuriamo gli hostname (nel caso siano configurati sul server DNS questa configurazione non è necessaria)
        
        Nel file /etc/hosts del server docker 10.0.0.8 inserire gli host coinvolti con questi comandi:
        echo '10.0.0.8  spidvalidator.DOMINIO_ENTE.it' >> /etc/hosts
        echo '10.0.0.9  spidauth.DOMINIO_ENTE.it' >> /etc/hosts
        echo '10.0.0.10 servizio_al_pubblico.DOMINIO_ENTE.it' >> /etc/hosts

6. Avviamo il container italia/spid-saml-check con questi comandi:

        ## Comando per eliminarlo: docker container stop spid_validator && docker container rm spid_validator
        docker run --name spid_validator -p 443:443 --env NODE_HTTPS_PORT=443 --add-host=spidvalidator.DOMINIO_ENTE.it:10.0.0.8 --add-host=spidauth.DOMINIO_ENTE.it:10.0.0.9 --add-host=servizio_al_pubblico.DOMINIO_ENTE.it:10.0.0.10 italia/spid-saml-check:1.9.2

7. Configuriamo il container per utilizzare la porta 443 invece che la 8443 e gli hostname scelti sopra:

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

8. Verifichiamo se l'installazione ha funzionato. Dovrebbero rispondere i seguenti link (le credenziali sono validator/validator):
* https://spidvalidator.DOMINIO_ENTE.it/
* https://spidvalidator.DOMINIO_ENTE.it/metadata.xml
* https://spidvalidator.DOMINIO_ENTE.it/demo
* https://spidvalidator.DOMINIO_ENTE.it/demo/metadata.xml

### 2. Creazione certificato per firma metadata

### 3. Installazione e configurazione Satosa

### 4. Configurazione servizio di test
