# Hashcat MVP

Protótipo fechado para simular o cadastro e auditar senhas sintéticas de até 8 caracteres usando MD5. O programa coleta dados fictícios de cadastro, gera associações locais e executa as campanhas do projeto dentro do tempo informado.

## Como executar

Requisitos: Linux x86_64 e um dispositivo OpenCL disponível (GPU ou CPU).

```bash
chmod +x run.sh
./run.sh
```

Na primeira execução, o script descompacta o RockYou. Python e uma instalação separada do Hashcat não são necessários. A primeira compilação do kernel OpenCL pode levar cerca de um minuto.

Se nenhum dispositivo aparecer, no Ubuntu/Debian é possível habilitar o processador com:

```bash
sudo apt install pocl-opencl-icd
```

## Ordem das campanhas

1. Associações expandidas dos dados informados.
2. Rules essenciais sobre bases pessoais.
3. Rules pesadas sobre bases pessoais.
4. Bases pessoais combinadas com o dicionário brasileiro curto.
5. Dicionário brasileiro direto e rules limitadas a 8 caracteres.
6. Listas opcionais: Top 100.000 e RockYou.
7. Máscaras numéricas de 4 a 8 posições.
8. Máscaras rápidas de formatos comuns.
9. Rules essenciais sobre o dicionário brasileiro ASCII.
10. Rules pesadas sobre o dicionário brasileiro ASCII.
11. Máscaras ampliadas.

O teste para quando encontra a senha, quando termina todas as campanhas ou quando vence o tempo informado.

## Resultados

Cada execução acrescenta o resultado em `audit_log.txt`. Esse arquivo não entra no Git. Ele contém os dados do cadastro e as senhas testadas em texto claro; use somente dados fictícios e compartilhe o log apenas com a equipe autorizada.

O pacote contém o executável do simulador, seu código-fonte, o runtime mínimo do Hashcat para MD5, wordlists, rules e masks usadas pelas campanhas.
