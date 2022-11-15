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

### 1

