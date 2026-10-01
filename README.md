# Hashcat MVP — worker de laboratório

Este pacote processa **somente contas inteiramente fictícias**. O cadastro no
FastAPI cria uma tarefa no PostgreSQL; o worker na UFF busca a tarefa pela API,
executa as campanhas e devolve status, tempo e campanha. O cadastro **não inicia**
o worker por conta própria.

## Arquivos principais

- `src/audit_worker.py`: consulta a fila da API e executa uma tarefa por padrão.
- `src/campaigns.py`: implementa as 51 campanhas e as associações do cadastro.
- `hashcat/`, `wordlists/`, `rules/`, `masks/`: recursos usados pelas campanhas.
- `tests/`: verificações do worker e dos recursos.

O login da aplicação usa Argon2id. O MD5 de laboratório fica na tarefa até o
resultado ser recebido; a API então o apaga. O worker não envia a senha
recuperada à API nem grava um log de senhas. Arquivos temporários, inclusive o
potfile, são descartados ao fim da tarefa.

## Executar uma tarefa

Requisitos: Linux x86_64, Python 3.10+, Hashcat/OpenCL funcionais, FastAPI com
`LAB_AUDIT_ENABLED=true`, e um `WORKER_TOKEN` próprio com pelo menos 32 caracteres.
Na UFF, a API deve ser alcançável por HTTPS autorizado ou por túnel SSH em
`127.0.0.1`; não exponha os endpoints internos à internet.

```bash
cd ~/hashcat-mvp
export AUDIT_API_URL=http://127.0.0.1:18000
read -r -s -p 'Token do worker: ' WORKER_TOKEN; echo
export WORKER_TOKEN
python3 src/audit_worker.py
```

O comando busca a tarefa pendente **mais antiga** e sai ao concluí-la. Se não
houver tarefa, imprime `Nenhuma tarefa pendente.`. Para buscar continuamente,
existe `python3 src/audit_worker.py --loop`, mas ele processa **toda** a fila;
use-o apenas sob supervisão e com uso da GPU autorizado pelo laboratório.
Interrompa com `Ctrl+C` e, ao terminar, use `unset WORKER_TOKEN AUDIT_API_URL`.

As campanhas param quando encontram a senha ou terminam todas as etapas. Não
há limite automático de três minutos; máscaras finais podem demorar muito mais.
Se o processo morrer depois de reivindicar uma tarefa, ela pode ficar em
`processing` e exigir intervenção. Não deixe este protótipo operando sem
supervisão.

## Verificar

```bash
python3 -m unittest tests.test_worker -q
python3 tests/smoke_test.py
```

O segundo teste executa o Hashcat com senhas sintéticas e pode demorar na
primeira compilação dos kernels OpenCL. Os recursos de terceiros mantêm suas
licenças em `LICENSES/`.
