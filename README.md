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

## Completion

Essa ferramenta possui complete para facilitar o uso em alguns shells. Execute o comando a baixo para listar os shells disponíveis:
```sh
sfn-xml-sign completion
```

Exemplo de como configurar no Bash do usuário atual:
```sh
mkdir -p ~/.local/share/bash-completion/completions
echo '. <(sfn-xml-sign completion bash)' > ~/.local/share/bash-completion/completions/sfn-xml-sign
. <(sfn-xml-sign completion bash)
```
