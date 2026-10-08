# SFN XML Sign

Ferramenta para assinar e validar XMLs trafegados no Sistema Financeiro Nacional (SFN).

## Exemplo de Uso

### Assinar XML

XML no padrão do [DICT](https://www.bcb.gov.br/estabilidadefinanceira/dict):
```sh
sfn-xml-sign sign dict data/client.crt data/client.key arquivo.xml
```

XML no padrão do [SPI](https://www.bcb.gov.br/estabilidadefinanceira/sistemapagamentosinstantaneos):
```sh
sfn-xml-sign sign spi data/client.crt data/client.key arquivo.xml
```

### Validar XML

XML no padrão do [DICT](https://www.bcb.gov.br/estabilidadefinanceira/dict):
```sh
sfn-xml-sign verify dict data/bcb.crt arquivo.xml
```

XML no padrão do [SPI](https://www.bcb.gov.br/estabilidadefinanceira/sistemapagamentosinstantaneos):
```sh
sfn-xml-sign verify spi data/client.crt arquivo.xml
```
