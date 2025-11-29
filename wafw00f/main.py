#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Copyright (C) 2024, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

import csv
import io
import json
import logging
import os
import random
import re
import sys
import string
import urllib.parse
from collections import defaultdict
from optparse import OptionParser

from wafw00f import __license__, __version__
from wafw00f.lib.asciiarts import Color, randomArt
from wafw00f.lib.evillib import waftoolsengine
from wafw00f.manager import load_plugins
from wafw00f.wafprio import wafdetectionsprio


class WAFW00F(waftoolsengine):

    xsstring = r'<script>alert("XSS");</script>'
    sqlistring = r'UNION SELECT ALL FROM information_schema AND " or SLEEP(5) or "'
    lfistring = r'../../etc/passwd'
    rcestring = r'/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com'
    xxestring = r'<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'

    def __init__(self, target='www.example.com', debuglevel=0, path='/',
                 followredirect=True, extraheaders={}, proxies=None, timeout=7):

        self.log = logging.getLogger('wafw00f')
        self.attackres = None
        waftoolsengine.__init__(self, target, debuglevel, path, proxies, followredirect, extraheaders, timeout)
        self.knowledge = {
            'generic': {
                'found': False,
                'reason': ''
            },
            'wafname': []
        }
        self.rq = self.normalRequest()

    def normalRequest(self):
        return self.Request()

    def customRequest(self, headers=None):
        return self.Request(
            headers=headers
        )

    def nonExistent(self):
        return self.Request(
            path=self.path + str(random.randrange(100, 999)) + '.html'
        )

    def xssAttack(self):
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.xsstring
            }
        )

    def xxeAttack(self):
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.xxestring
            }
        )

    def lfiAttack(self):
        return self.Request(
            path=self.path + self.lfistring
        )

    def centralAttack(self):
        '''
        作为「攻击请求生成器」，构造包含 3 种攻击 payload 的请求参数，并调用 self.Request 方法发送请求
        '''
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.xsstring,
                create_random_param_name(): self.sqlistring,
                create_random_param_name(): self.lfistring
            }
        )

    def sqliAttack(self):
        return self.Request(
            path=self.path,
            params={
                create_random_param_name(): self.sqlistring
            }
        )

    def osciAttack(self):
        return self.Request(
            path=self.path,
            params= {
                create_random_param_name(): self.rcestring
            }
        )

    def performCheck(self, request_method):
        r = request_method()
        if r is None:
            raise RequestBlocked()
        return r, r.url

    # Most common attacks used to detect WAFs
    attcom = [xssAttack, sqliAttack, lfiAttack]
    attacks = [xssAttack, xxeAttack, lfiAttack, sqliAttack, osciAttack]

    def genericdetect(self):
        '''
        指纹识别
        '''
        reason = ''
        reasons = [
            '阻断操作发生在连接/数据包层面。',
            '检测到攻击行为时，服务器返回的标头信息发生变化。',
            '使用攻击性字符串时，服务器返回了不同的响应状态码。',
            '对于常规请求，服务器关闭了连接。',
            '当请求并非源自浏览器时，服务器返回的响应内容有所不同。'
        ]
        try:
            # Testing for no user-agent response. Detects almost all WAFs out there.
            # 发送一个正常的、带有完整 User-Agent 头的请求，并获取响应 resp1。
            resp1, _ = self.performCheck(self.normalRequest)
            # 移除 User-Agent 头的影响
            if 'User-Agent' in self.headers:
                self.headers.pop('User-Agent')  # Deleting the user-agent key from object not dict.
            resp3 = self.customRequest(headers=self.headers)
            if resp3 is not None and resp1 is not None:
                #如果 resp1 和 resp3 的 HTTP 状态码 不一样
                if resp1.status_code != resp3.status_code:
                    self.log.info('服务器在请求未包含User-Agent标头时返回了不同的响应。')
                    reason = reasons[4]
                    reason += '\r\n'
                    reason += '正常请求的响应状态码为"%s",' % resp1.status_code
                    reason += '而修改后的请求的响应状态码为"%s"' % resp3.status_code
                    self.knowledge['generic']['reason'] = reason
                    self.knowledge['generic']['found'] = True
                    return True

            # Testing the status code upon sending a xss attack
            resp2, xss_url = self.performCheck(self.xssAttack)
            if resp1.status_code != resp2.status_code:
                self.log.info('当尝试使用XSS攻击向量时，服务器返回了不同的响应。')
                reason = reasons[2]
                reason += '\r\n'
                reason += '正常请求的响应状态码为"%s",' % resp1.status_code
                reason += '而针对跨站脚本攻击的响应状态码为"%s"' % resp2.status_code
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return xss_url

            # Testing the status code upon sending a lfi attack
            resp2, lfi_url = self.performCheck(self.lfiAttack)
            if resp1.status_code != resp2.status_code:
                self.log.info('当尝试目录遍历时，服务器返回了不同的响应。')
                reason = reasons[2]
                reason += '\r\n'
                reason += '正常请求的响应状态码为"%s",' % resp1.status_code
                reason += '而针对文件包含攻击的响应状态码为"%s"' % resp2.status_code
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return lfi_url

            # Testing the status code upon sending a sqli attack
            resp2, sqli_url = self.performCheck(self.sqliAttack)
            if resp1.status_code != resp2.status_code:
                self.log.info('当尝试SQL注入攻击时，服务器返回了不同的响应。')
                reason = reasons[2]
                reason += '\r\n'
                reason += '正常请求的响应状态码为"%s",' % resp1.status_code
                reason += '而针对SQL注入攻击的响应状态码为"%s"' % resp2.status_code
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return sqli_url

            # Checking for the Server header after sending malicious requests
            normalserver, attackresponse_server = '', ''
            response = self.attackres
            # 对比 Server 响应头
            if 'server' in resp1.headers:
                normalserver = resp1.headers.get('Server')
            # 从最近一次攻击请求的响应 self.attackres 中获取 Server 头信息。
            if response is not None and 'server' in response.headers:
                attackresponse_server = response.headers.get('Server')
            if attackresponse_server != normalserver:
                self.log.info('服务器标头发生变化，可能检测到WAF。')
                self.log.debug('攻击响应的服务器标头：%s' % attackresponse_server)
                self.log.debug('正常响应的服务器标头：%s' % normalserver)
                reason = reasons[1]
                reason += '\r\n正常响应的服务器标头为"%s",' % normalserver
                reason += '而攻击响应的服务器标头为"%s",' % attackresponse_server
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return True

        # If at all request doesn't go, press F
        except RequestBlocked:
            self.knowledge['generic']['reason'] = reasons[0]
            self.knowledge['generic']['found'] = True
            return True
        return False

    def matchHeader(self, headermatch, attack=False):
        '''
        检查 HTTP 响应头（Response Headers）中是否包含防火墙的特定字符。
        headermatch：
        第一个元素是要检查的响应头名称（例如 'Content-Type', 'Set-Cookie'）。
        第二个元素是用于匹配的正则表达式模式（例如 'text/html', 'PHPSESSID'）。
        attack=False:
        这是一个布尔值的可选参数，用作开关，决定函数是检查哪一个响应对象。
        '''
        if attack:
            #attackres是前面构造恶意请求返回的数据
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return

        header, match = headermatch
        #r.headers 通常是一个类似字典的对象，包含了所有的响应头。
        #.get(header) 方法会尝试获取名为 header 的响应头的值。如果该响应头不存在，它会返回 None，而不是抛出异常。
        headerval = r.headers.get(header)
        if headerval:
            # set-cookie can have multiple headers, python gives it to us
            # concatinated with a comma
            if header == 'Set-Cookie':
                headervals = headerval.split(', ')
            else:
                headervals = [headerval]
            for headerval in headervals:
                # 使用正则表达式进行匹配
                if re.search(match, headerval, re.I):
                    return True
        return False

    def matchStatus(self, statuscode, attack=True):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return
        if r.status_code == statuscode:
            return True
        return False

    def matchCookie(self, match, attack=False):
        return self.matchHeader(('Set-Cookie', match), attack=attack)

    def matchReason(self, reasoncode, attack=True):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return
        # We may need to match multiline context in response body
        if str(r.reason) == reasoncode:
            return True
        return False

    def matchContent(self, regex, attack=True):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return
        # We may need to match multiline context in response body
        if re.search(regex, r.text, re.I):
            return True
        return False

    #waf检测目标
    wafdetections = dict()

    #动态加载一个指定目录（plugins）下的所有 Python 模块作为 “插件”
    plugin_dict = load_plugins()
    result_dict = {}
    for plugin_module in plugin_dict.values():
        wafdetections[plugin_module.NAME] = plugin_module.is_waf
    # Check for prioritized ones first, then check those added externally
    checklist = wafdetectionsprio
    # 这里的-是集合差集操作
    checklist += list(set(wafdetections.keys()) - set(checklist))

    def identwaf(self, findall=False):
        '''
        如果 findall 为 False（默认情况），则函数在检测到第一个匹配的 WAF 后就会立即停止搜索。
        如果 findall 为 True，则函数会继续检测，尝试找出所有可能匹配的 WAF。
        '''
        detected = list()
        try:
            # 构造恶意请求。
            self.attackres, xurl = self.performCheck(self.centralAttack)
        except RequestBlocked:
            return detected, None
        for wafvendor in self.checklist:
            self.log.info('Checking for %s' % wafvendor)
            # 对每个文件进行遍历，直到找到，返回真。
            if self.wafdetections[wafvendor](self):
                detected.append(wafvendor)
                if not findall:
                    break
        self.knowledge['wafname'] = detected
        return detected, xurl

def calclogginglevel(verbosity):
    default = 40  # errors are printed out
    level = default - (verbosity * 10)
    if level < 0:
        level = 0
    return level

def buildResultRecord(url, waf, evil_url=None):
    '''
    建一个标准化的结果记录字典，
    '''
    result = {}
    result['url'] = url
    if waf:
        result['detected'] = True
        if waf == 'generic':
            result['trigger_url'] = evil_url
            result['firewall'] = 'Generic'
            result['manufacturer'] = 'Unknown'
        else:
            result['trigger_url'] = evil_url
            result['firewall'] = waf.split('(')[0].strip()
            result['manufacturer'] = waf.split('(')[1].replace(')', '').strip()
    else:
        result['trigger_url'] = evil_url
        result['detected'] = False
        result['firewall'] = 'None'
        result['manufacturer'] = 'None'
    return result

def getTextResults(res=[]):
    # leaving out some space for future possibilities of newer columns
    # newer columns can be added to this tuple below
    keys = ('detected')
    res = [({key: ba[key] for key in ba if key not in keys}) for ba in res]
    rows = []
    for dk in res:
        p = [str(x) for _, x in dk.items()]
        rows.append(p)
    for m in rows:
        m[1] = '%s (%s)' % (m[1], m[2])
        m.pop()
    defgen = [
        (max([len(str(row[i])) for row in rows]) + 3)
        for i in range(len(rows[0]))
    ]
    rwfmt = ''.join(['{:>'+str(dank)+'}' for dank in defgen])
    textresults = []
    for row in rows:
        textresults.append(rwfmt.format(*row))
    return textresults

def create_random_param_name(size=8, chars=string.ascii_lowercase):
    '''
    生成一个随机的字符串，用于作为 HTTP 请求的「参数名」
    '''
    return ''.join(random.choice(chars) for _ in range(size))

def disableStdOut():
    sys.stdout = None

def enableStdOut():
    sys.stdout = sys.__stdout__

def getheaders(fn):
    headers = {}
    # 文件存在性检查
    if not os.path.exists(fn):
        logging.getLogger('wafw00f').critical('Headers file "%s" does not exist!' % fn)
        return
    with io.open(fn, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            _t = line.split(':', 2)
            if len(_t) == 2:
                # map 对象会被转换为一个列表（在 Python 3 中需要显式转换，但在解包时可以直接使用）
                # 解包赋值
                h, v = map(lambda x: x.strip(), _t)
                headers[h] = v
    return headers

class RequestBlocked(Exception):
    pass

def main():
    parser = OptionParser(usage='%prog url1 [url2 [url3 ... ]]\r\nexample: %prog http://www.victim.org/')
    # 启用了就为1
    parser.add_option('-v', '--verbose', action='count', dest='verbose', default=0,
                      help='启用详细信息，多个-v选项增加详细信息')
    parser.add_option('-a', '--findall', action='store_true', dest='findall', default=False,
                      help='查找所有匹配特征的WAF，不要在找到第一个后就停止测试。')
    parser.add_option('-r', '--noredirect', action='store_false', dest='followredirect',
                      default=True, help='不跟随 3xx 响应给出的重定向')
    parser.add_option('-t', '--test', dest='test', help='测试一个特定的WAF')
    parser.add_option('-o', '--output', dest='output', help='Write output to csv, json or text file depending on file extension. For stdout, specify - as filename.',
                      default=None)
    parser.add_option('-f', '--format', dest='format', help='强制输出格式为CSV、JSON或文本。',
                      default=None)
    parser.add_option('-i', '--input-file', dest='input', help='Read targets from a file. Input format can be csv, json or text. For csv and json, a `url` column name or element is required.',
                      default=None)
    parser.add_option('-l', '--list', dest='list', action='store_true',
                      default=False, help='列出WAFW00F能够检测到的所有waf')
    parser.add_option('-p', '--proxy', dest='proxy', default=None,
                      help='Use an HTTP proxy to perform requests, examples: http://hostname:8080, socks5://hostname:1080, http://user:pass@hostname:8080')
    parser.add_option('--version', '-V', dest='version', action='store_true',
                      default=False, help='Print out the current version of WafW00f and exit.')
    parser.add_option('--headers', '-H', dest='headers', action='store', default=None,
                      help='Pass custom headers via a text file to overwrite the default header set.')
    parser.add_option('-T', '--timeout', dest='timeout', action='store', default=7, type=int,
                      help='Set the timeout for the requests.')
    parser.add_option('--no-colors', dest='colors', action='store_false',
                      default=True, help='Disable ANSI colors in output.')

    options, args = parser.parse_args()
    #日志信息的输出级别。
    '''
        DEBUG	10	调试信息（最详细）	开发阶段排查问题
        INFO	20	普通信息	程序正常运行的关键节点提示
        WARNING	30	警告信息	潜在风险（如参数不规范）
        ERROR	40	错误信息	功能执行失败（如文件读取失败）
        CRITICAL	50	严重错误	程序即将崩溃（如内存耗尽）
    '''
    logging.basicConfig(level=calclogginglevel(options.verbose))
    #创建/获取一个名为 'wafw00f' 的日志记录器（Logger）对象
    log = logging.getLogger('wafw00f')
    if options.output == '-':
        disableStdOut()

    # Windows based systems do not support ANSI sequences,
    # hence not displaying them.
    if not options.colors or 'win' in sys.platform:
        Color.disable()

    print(randomArt())
    (W,Y,G,R,B,C,E) = Color.unpack()

    # 列出WAFW00F能够检测到的所有waf
    if options.list:
        print('[+] Can test for these WAFs:\r\n')
        try:
            # 将一个 “名称 (数值)”格式的字符串列表，解析成一个包含多个 [名称, 数值] 子列表的列表
            m = [i.replace(')', '').split(' (') for i in wafdetectionsprio]
            print(R+'  WAF Name'+' '*24+'Manufacturer\n  '+'-'*8+' '*24+'-'*12+'\n')
            max_len = max(len(str(x)) for k in m for x in k)
            for inner in m:
                first = True
                for elem in inner:
                    if first:
                        text = Y+'  {:<{}} '.format(elem, max_len+2)
                        first = False
                    else:
                        text = W+'{:<{}} '.format(elem, max_len+2)
                    print(text, E, end='')
                print()
            sys.exit(0)
        except Exception:
            return
    if options.version:
        print('[+] The version of WAFW00F you have is %sv%s%s' % (B, __version__, E))
        print('[+] WAFW00F is provided under the %s%s%s license.' % (C, __license__, E))
        return
    #理用户提供的额外 HTTP 请求头。
    extraheaders = {}
    if options.headers:
        log.info('Getting extra headers from %s' % options.headers)
        extraheaders = getheaders(options.headers)
        if extraheaders is None:
            # parser.error(...) 会打印一条指定的错误信息，并终止程序的运行。
            parser.error('请提供一个正确格式的头文件，文件中的每一行应该是 头名称: 值 这样的格式（例如 User-Agent: TestWAF）。')
    if len(args) == 0 and not options.input:
        parser.error('No test target specified.')

    #check if input file is present
    if options.input:
        log.debug('Loading file "%s"' % options.input)
        try:
            #  处理 JSON 文件
            if options.input.endswith('.json'):
                with open(options.input) as f:
                    try:
                        urls = json.loads(f.read())
                    except json.decoder.JSONDecodeError:
                        log.critical('JSON file %s did not contain well-formed JSON', options.input)
                        sys.exit(1)
                log.info('Found: %s urls to check.' %(len(urls)))
                targets = [ item['url'] for item in urls ]
            #处理 CSV 文件
            elif options.input.endswith('.csv'):
                columns = defaultdict(list)
                with open(options.input) as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        for (k,v) in row.items():
                            columns[k].append(v)
                targets = columns['url']
            #处理普通文本文件
            else:
                with open(options.input) as f:
                    targets = [x for x in f.read().splitlines()]
        except FileNotFoundError:
            log.error('File %s could not be read. No targets loaded.', options.input)
            sys.exit(1)
    else:
        targets = args
    results = []
    for target in targets:
        if not target.startswith('http'):
            log.info('URL %s 应该以 http:// 或 https:// 开头 .. 修复（可能会使其无法使用）' % target)
            target = 'https://' + target
        print('[*] Checking %s' % target)
        pret = urllib.parse.urlparse(target)
        if pret is None:
            log.critical('url %s 格式不正确' % target)
            sys.exit(1)
        log.info('starting wafw00f on %s' % target)
        proxies = dict()
        # 代理
        if options.proxy:
            proxies = {
                'http': options.proxy,
                'https': options.proxy,
            }
        # 目标，debug等级，路径，3xx是否跳转，自选请求头，代理，超时时间
        attacker = WAFW00F(target, debuglevel=options.verbose, path=pret.path,
                    followredirect=options.followredirect, extraheaders=extraheaders,
                        proxies=proxies, timeout=options.timeout)
        if attacker.rq is None:
            log.error('Site %s appears to be down' % pret.hostname)
            continue
        # 测试一个特定的WAF
        if options.test:
            if options.test in attacker.wafdetections:
                waf = attacker.wafdetections[options.test](attacker)
                if waf:
                    print('[+] The site %s%s%s is behind %s%s%s WAF.' % (B, target, E, C, options.test, E))
                else:
                    print('[-] WAF %s was not detected on %s' % (options.test, target))
            else:
                print('[-] WAF %s was not found in our list\r\nUse the --list option to see what is available' % options.test)
            return
        waf, xurl = attacker.identwaf(options.findall)
        log.info('Identified WAF: %s' % waf)
        if len(waf) > 0:
            for i in waf:
                results.append(buildResultRecord(target, i, xurl))
            print('[+] The site %s%s%s is behind %s%s%s WAF.' % (B, target, E, C, (E+' and/or '+C).join(waf), E))
        if (options.findall) or len(waf) == 0:
            print('[+] Generic Detection results:')
            # 相当于指纹识别
            generic_url = attacker.genericdetect()
            if generic_url:
                log.info('通用检测结果：%s' % attacker.knowledge['generic']['reason'])
                print('[*] 网站 %s 似乎部署了WAF或其他安全解决方案' % target)
                print('[~] 原因：%s' % attacker.knowledge['generic']['reason'])
                results.append(buildResultRecord(target, 'generic', generic_url))
            else:
                print('[-] 通用检测未发现WAF')
                results.append(buildResultRecord(target, None, None))
        print('[~] 发起的请求数量：%s' % attacker.requestnumber)
    #print table of results
    if len(results) > 0:
        log.info('Found: %s matches.' % (len(results)))
    if options.output:
        if options.output == '-':
            enableStdOut()
            if options.format == 'json':
                json.dump(results, sys.stdout, indent=2, sort_keys=True)
            elif options.format == 'csv':
                csvwriter = csv.writer(sys.stdout, delimiter=',', quotechar='"',
                    quoting=csv.QUOTE_MINIMAL)
                count = 0
                for result in results:
                    if count == 0:
                        header = result.keys()
                        csvwriter.writerow(header)
                        count += 1
                    csvwriter.writerow(result.values())
            else:
                print(os.linesep.join(getTextResults(results)))
        elif options.output.endswith('.json'):
            log.debug('Exporting data in json format to file: %s' % (options.output))
            with open(options.output, 'w') as outfile:
                json.dump(results, outfile, indent=2, sort_keys=True)
        elif options.output.endswith('.csv'):
            log.debug('Exporting data in csv format to file: %s' % (options.output))
            with open(options.output, 'w') as outfile:
                csvwriter = csv.writer(outfile, delimiter=',', quotechar='"',
                    quoting=csv.QUOTE_MINIMAL)
                count = 0
                for result in results:
                    if count == 0:
                        header = result.keys()
                        csvwriter.writerow(header)
                        count += 1
                    csvwriter.writerow(result.values())
        else:
            log.debug('Exporting data in text format to file: %s' % (options.output))
            if options.format == 'json':
                with open(options.output, 'w') as outfile:
                    json.dump(results, outfile, indent=2, sort_keys=True)
            elif options.format == 'csv':
                with open(options.output, 'w') as outfile:
                    csvwriter = csv.writer(outfile, delimiter=',', quotechar='"',
                        quoting=csv.QUOTE_MINIMAL)
                    count = 0
                    for result in results:
                        if count == 0:
                            header = result.keys()
                            csvwriter.writerow(header)
                            count += 1
                        csvwriter.writerow(result.values())
            else:
                with open(options.output, 'w') as outfile:
                    outfile.write(os.linesep.join(getTextResults(results)))

if __name__ == '__main__':
    version_info = sys.version_info
    if version_info.major < 3 or (version_info.major == 3 and version_info.minor < 6):
        sys.stderr.write('Your version of python is way too old... please update to 3.6 or later\r\n')
    main()
