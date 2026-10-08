# SFN XML Sign

Ferramenta para assinar e validar XMLs trafegados no Sistema Financeiro Nacional (SFN).

## Exemplo de Uso

[![Vídeo no asciinema](https://asciinema.org/a/1267861.svg)](https://asciinema.org/a/1267861)

### Assinar XML

XML no padrão do [DICT](https://www.bcb.gov.br/estabilidadefinanceira/dict):
```sh
sfn-xml-sign sign dict data/client.crt data/client.key example-dict-message.xml
```

XML no padrão do [SPI](https://www.bcb.gov.br/estabilidadefinanceira/sistemapagamentosinstantaneos):
```sh
sfn-xml-sign sign spi data/client.crt data/client.key example-spi-message.xml
```

### Validar XML

XML no padrão do [DICT](https://www.bcb.gov.br/estabilidadefinanceira/dict):
```sh
sfn-xml-sign verify dict data/bcb.crt example-dict-message.xml
```

XML no padrão do [SPI](https://www.bcb.gov.br/estabilidadefinanceira/sistemapagamentosinstantaneos):
```sh
sfn-xml-sign verify spi data/client.crt example-spi-message.xml
```

## Instação

Compile o projeto executando o comando `make`. Após isso copie o arquivo `sfn-xml-sign` para algum diretório do `$PATH` como `/usr/local/bin`. Exemplo:

```sh
make
sudo cp sfn-xml-sign /usr/local/bin
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
