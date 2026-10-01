# Packet Filter


## Building ns-3

Após clonar o repositório, configure e builde o ns-3 com:

```shell
./ns3 configure --enable-examples --enable-tests
```


```shell
./ns3 build
```


## Arquivos importantes

* **src/lte/model/lte-pdcp.cc**: ponto de interceptação de pacotes e envio ao socket
* **scratch/xapp_packet_filter.py**: código python para recepção dos pacotes e tomada de decisão
* **scratch/lte-xapp.py**: arquivo com a configuração do ambiente de simulação


## Execução
Para executar a simulação, siga as seguintes execuções, na mesma ordem:
1. python3 scratch/xapp_packet_filter.py
2. ./ns3 run lte-xapp
