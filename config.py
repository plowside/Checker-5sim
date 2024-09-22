### MAIN
max_concurrent_tasks = 3 # Сколько потоков
accounts_path = 'data/accounts.txt' # Файл с аккаунтами
valid_save_path = 'data/valid.txt' # Путь до файла с валидом
recheck_save_path = 'data/recheck.txt' # Путь до файла для повторной проверки
invalid_save_path = 'data/invalid.txt' # Путь до файла с невалидом
captcha_solver_key = '23d35eea0aa265dbc35a28790ab8afa4' # Ключ сервиса решения капчи
captcha_solver_service = { # Сервис решения капчи
	'CapGuru': True
}

### PROXY
proxy_path = 'data/proxy.txt' # Файл с прокси
proxy_protocol = { # Протокол прокси. Выбирать один
	'http': True,
	'socks5': False
}