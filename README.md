# Hashcat MVP

Protótipo de laboratório para simular o cadastro e auditar senhas sintéticas de até 8 caracteres usando MD5. O programa coleta dados fictícios de cadastro, gera associações locais e executa as campanhas do projeto dentro do tempo informado.

## Como executar

Requisitos: Linux x86_64 e um dispositivo OpenCL disponível (GPU ou CPU). Python 3.10+ é recomendado para evitar diferenças de `glibc` entre computadores.

```bash
chmod +x run.sh
./run.sh
```

O pacote já inclui o recorte do RockYou com candidatos UTF-8 de até 8 caracteres, pronto para uso. `run.sh` usa Python 3.10+ quando disponível; caso contrário, tenta o executável portátil. Uma instalação separada do Hashcat não é necessária. A primeira compilação do kernel OpenCL pode levar cerca de um minuto.

Se nenhum dispositivo aparecer, no Ubuntu/Debian é possível habilitar o processador com:

```bash
sudo apt install pocl-opencl-icd
```

## Worker da API (somente contas sintéticas)

O modo interativo acima continua separado. O worker em `src/audit_worker.py` busca uma tarefa da API, executa as mesmas campanhas usando **apenas o MD5 recebido** e devolve status, tempo e campanha. Não envia nem persiste a senha encontrada: o potfile temporário do Hashcat pode contê-la durante a execução e é apagado ao fim da tarefa. O login da aplicação continua usando Argon2id.

Primeiro, rode FastAPI/PostgreSQL localmente conforme o guia em `gt-tecseg-integration/backend/README.md` (repositório vizinho), com `LAB_AUDIT_ENABLED=true` e um `WORKER_TOKEN` aleatório de pelo menos 32 caracteres no `backend/.env`. Use um banco de laboratório que contenha **somente contas inteiramente fictícias**: o worker reivindica a tarefa pendente mais antiga, não necessariamente a última conta cadastrada. Em outro terminal, nesta pasta:

```bash
export AUDIT_API_URL=http://127.0.0.1:8000
read -rsp 'Token do worker: ' WORKER_TOKEN; echo; export WORKER_TOKEN
python3 src/audit_worker.py
```

Por padrão, ele processa no máximo uma tarefa (`Nenhuma tarefa pendente` se a fila estiver vazia). `--loop` busca continuamente, com intervalo padrão de 5 segundos; use somente depois de validar uma tarefa supervisionada. Cada tarefa termina ao encontrar a senha ou concluir as 51 campanhas; não há prazo automático no worker. As máscaras finais podem demorar muito mais que três minutos dependendo do equipamento. `Ctrl+C` interrompe a tarefa e a registra como erro. O worker rejeita HTTP fora de `localhost`/loopback: no servidor da UFF, use HTTPS autorizado ou um túnel SSH que entregue a API na porta loopback do servidor. **Não exponha a porta interna da API nem o token na internet.**

O protocolo ainda não tem recuperação automática se o processo morrer após reivindicar uma tarefa; ela fica como `processing` e exige intervenção antes de testar novamente. Por isso, esta etapa serve para teste supervisionado, não para execução autônoma prolongada. Para conferir o worker sem GPU ou rede: `python3 -m unittest tests.test_worker -v`.

## Ordem das campanhas

1. Consulta direta: Top 100 mil (até 8) e BR completo.
2. Máscara numérica completa de 1 a 8 dígitos.
3. Associação direta; depois, bases curtas com anos plausíveis e símbolos na mesma rule.
4. Associação com números e símbolos, RockYou (até 8), rules pessoais e palavras brasileiras curtas.
5. Dicionário brasileiro com rules ajustadas ao limite de 8 caracteres.
6. Seis híbridos adicionais: bases de até 3/4/5 caracteres com 4/3/2 dígitos e símbolo, nas duas ordens. As bases combinam termos BR curtos e variações do cadastro.
7. Híbridos anteriores de palavra brasileira + dígitos/símbolo, máscaras estruturadas e RockYou com uma rule curta.
8. Rules pesadas sobre bases pessoais e rules essenciais/pesadas sobre o BR ASCII.
9. Máscaras amplas por último.

Cada subcampanha aparece no terminal com seu nome, posição, tempo restante e tempo gasto. As duas primeiras consultas comparam MD5 localmente, sem o custo de iniciar o Hashcat; as demais executam o Hashcat. As associações só são preparadas se as consultas iniciais e a máscara numérica não encontrarem a senha. O teste para quando encontra a senha, quando termina todas as campanhas, quando vence o tempo informado ou quando ocorre um erro operacional. O resultado distingue cobertura completa, prazo esgotado e falha; as etapas finais podem não ser alcançadas em testes curtos.

A rule prioritária usa o ano de nascimento e os anos de três anos atrás até o próximo ano, combinados com símbolos comuns. Essas regras são criadas no início da sessão; os seis híbridos usam máscaras de dígitos e símbolos sobre bases de até 3, 4 ou 5 caracteres. Essas sete etapas respeitam o limite do protótipo de oito caracteres.

Antes de compartilhar resultados, valide o pacote no próprio computador/servidor com `python3 tests/smoke_test.py`. Ele usa apenas hashes e senhas sintéticos e confere as 51 campanhas, arquivos, máscaras, rules e os modos `0`, `1`, `3`, `6` e `7`. O primeiro teste pode levar mais tempo por causa da compilação dos kernels OpenCL.

## Resultados

Cada execução acrescenta o resultado em `audit_log.txt`. Esse arquivo não entra no Git. Ele contém os dados do cadastro e as senhas testadas em texto claro; use somente dados fictícios e compartilhe o log apenas com a equipe autorizada.

O pacote contém o executável do simulador, seu código-fonte, o runtime do Hashcat para MD5, wordlists, rules e masks usadas pelas campanhas. As sublistas `max-4`, `max-6` e `max-7` são usadas para não ultrapassar o limite de 8 caracteres nas rules que acrescentam caracteres.
